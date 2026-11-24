import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';
import 'package:basic_utils/basic_utils.dart';
import 'package:crypto/crypto.dart';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:shared_preferences/shared_preferences.dart';

// ---------- tiny protobuf helpers ----------
List<int> varint(int v) {
  final o = <int>[];
  while (v > 0x7f) {
    o.add((v & 0x7f) | 0x80);
    v >>= 7;
  }
  o.add(v);
  return o;
}

List<int> fVar(int f, int v) => [...varint(f << 3), ...varint(v)];
List<int> fBytes(int f, List<int> b) =>
    [...varint((f << 3) | 2), ...varint(b.length), ...b];
List<int> fStr(int f, String s) => fBytes(f, utf8.encode(s));

Map<int, dynamic> parse(List<int> b) {
  final m = <int, dynamic>{};
  int i = 0;
  int rv() {
    int r = 0, s = 0;
    while (true) {
      final x = b[i++];
      r |= (x & 0x7f) << s;
      if (x < 0x80) break;
      s += 7;
    }
    return r;
  }

  while (i < b.length) {
    final t = rv();
    final f = t >> 3, w = t & 7;
    if (w == 0) {
      m[f] = rv();
    } else if (w == 2) {
      final l = rv();
      m[f] = Uint8List.fromList(b.sublist(i, i + l));
      i += l;
    } else if (w == 5) {
      i += 4;
    } else if (w == 1) {
      i += 8;
    } else {
      break;
    }
  }
  return m;
}

// ---------- framed TLS connection ----------
class Conn {
  final SecureSocket sock;
  final _buf = <int>[];
  final _ctl = StreamController<Uint8List>();
  late final StreamIterator<Uint8List> _it = StreamIterator(_ctl.stream);

  Conn(this.sock) {
    sock.listen((d) {
      _buf.addAll(d);
      _drain();
    }, onError: (e) {
      if (!_ctl.isClosed) _ctl.addError(e);
    }, onDone: () {
      if (!_ctl.isClosed) _ctl.close();
    });
  }

  Stream<Uint8List> get stream => _ctl.stream;

  void _drain() {
    while (true) {
      int i = 0, len = 0, s = 0;
      while (true) {
        if (i >= _buf.length) return;
        final x = _buf[i++];
        len |= (x & 0x7f) << s;
        if (x < 0x80) break;
        s += 7;
      }
      if (_buf.length < i + len) return;
      _ctl.add(Uint8List.fromList(_buf.sublist(i, i + len)));
      _buf.removeRange(0, i + len);
    }
  }

  Future<Map<int, dynamic>> next() async {
    final ok = await _it.moveNext().timeout(const Duration(seconds: 30));
    if (!ok) throw 'connection closed';
    return parse(_it.current);
  }

  void send(List<int> m) => sock.add([...varint(m.length), ...m]);
  void close() => sock.destroy();
}

// ---------- certificate identity ----------
List<int> pemToDer(String pem) => base64.decode(pem
    .split('\n')
    .map((l) => l.trim())
    .where((l) => l.isNotEmpty && !l.startsWith('-----'))
    .join());

/// Extract RSA modulus and exponent (no leading zeros) from a certificate DER.
List<List<int>> rsaNE(List<int> der) {
  const oid = [0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01];
  int p = -1;
  for (int i = 0; i < der.length - oid.length; i++) {
    bool ok = true;
    for (int j = 0; j < oid.length; j++) {
      if (der[i + j] != oid[j]) {
        ok = false;
        break;
      }
    }
    if (ok) {
      p = i + oid.length;
      break;
    }
  }
  if (p < 0) throw 'RSA key not found';
  int pos = p + 2; // skip NULL (05 00)
  int rl() {
    int l = der[pos++];
    if (l < 0x80) return l;
    final n = l & 0x7f;
    l = 0;
    for (int i = 0; i < n; i++) {
      l = (l << 8) | der[pos++];
    }
    return l;
  }

  if (der[pos++] != 0x03) throw 'bad der';
  rl();
  pos++; // unused bits
  if (der[pos++] != 0x30) throw 'bad der';
  rl();
  List<int> readInt() {
    if (der[pos++] != 0x02) throw 'bad der';
    final l = rl();
    var v = der.sublist(pos, pos + l);
    pos += l;
    while (v.length > 1 && v[0] == 0) {
      v = v.sublist(1);
    }
    return v;
  }

  final n = readInt();
  final e = readInt();
  return [n, e];
}

class Identity {
  final String cert, key;
  Identity(this.cert, this.key);

  static Future<Identity> load() async {
    final p = await SharedPreferences.getInstance();
    var c = p.getString('cert');
    var k = p.getString('key');
    if (c == null || k == null) {
      final pair = CryptoUtils.generateRSAKeyPair(keySize: 2048);
      final priv = pair.privateKey as RSAPrivateKey;
      final pub = pair.publicKey as RSAPublicKey;
      final csr = X509Utils.generateRsaCsrPem({'CN': 'atvremote'}, priv, pub);
      c = X509Utils.generateSelfSignedCertificate(priv, csr, 3650);
      k = CryptoUtils.encodeRSAPrivateKeyToPem(priv);
      await p.setString('cert', c);
      await p.setString('key', k);
    }
    return Identity(c, k);
  }

  SecurityContext ctx() => SecurityContext(withTrustedRoots: false)
    ..useCertificateChainBytes(utf8.encode(cert))
    ..usePrivateKeyBytes(utf8.encode(key));
}

// ---------- pairing (port 6467) ----------
List<int> pm(List<int> body) => [...fVar(1, 2), ...fVar(2, 200), ...body];

class Pairing {
  final Conn c;
  final List<List<int>> serverNE;
  final Identity id;
  Pairing(this.c, this.serverNE, this.id);

  static Future<Pairing> start(String host, Identity id) async {
    final s = await SecureSocket.connect(host, 6467,
        context: id.ctx(),
        onBadCertificate: (_) => true,
        timeout: const Duration(seconds: 8));
    final c = Conn(s);
    final ne = rsaNE(s.peerCertificate!.der);
    Future<void> step(List<int> msg) async {
      c.send(msg);
      final r = await c.next();
      if (r[2] != 200) throw 'pairing rejected';
    }

    await step(pm(fBytes(10, [...fStr(1, 'atvremote'), ...fStr(2, 'Phone Remote')])));
    final enc = [...fVar(1, 3), ...fVar(2, 6)];
    await step(pm(fBytes(20, [...fBytes(1, enc), ...fVar(3, 1)])));
    await step(pm(fBytes(30, [...fBytes(1, enc), ...fVar(2, 1)])));
    return Pairing(c, ne, id);
  }

  Future<void> finish(String pin) async {
    pin = pin.trim();
    if (pin.length != 6) throw 'code must be 6 characters';
    final mine = rsaNE(pemToDer(id.cert));
    final h = pin.substring(2);
    final nonce = [
      int.parse(h.substring(0, 2), radix: 16),
      int.parse(h.substring(2, 4), radix: 16)
    ];
    final hash = sha256.convert([
      ...mine[0], ...mine[1], ...serverNE[0], ...serverNE[1], ...nonce
    ]).bytes;
    c.send(pm(fBytes(40, fBytes(1, hash))));
    final r = await c.next();
    c.close();
    if (r[2] != 200) throw 'wrong code';
  }
}

// ---------- remote control (port 6466) ----------
class Remote {
  Conn? c;
  bool ready = false;
  void Function(bool) onState = (_) {};

  Future<void> connect(String host, Identity id) async {
    close();
    final s = await SecureSocket.connect(host, 6466,
        context: id.ctx(),
        onBadCertificate: (_) => true,
        timeout: const Duration(seconds: 6));
    final conn = Conn(s);
    c = conn;
    void down() {
      ready = false;
      onState(false);
    }

    conn.stream.listen((m) {
      final r = parse(m);
      if (r.containsKey(1)) {
        conn.send(fBytes(1, [
          ...fVar(1, 622),
          ...fBytes(2, [
            ...fStr(1, 'Phone'),
            ...fStr(2, 'Remote'),
            ...fVar(3, 1),
            ...fStr(4, '1'),
            ...fStr(5, 'atvremote'),
            ...fStr(6, '1.0.0'),
          ])
        ]));
      } else if (r.containsKey(2)) {
        conn.send(fBytes(2, fVar(1, 622)));
        ready = true;
        onState(true);
      } else if (r.containsKey(8)) {
        final p = parse(r[8]);
        conn.send(fBytes(9, fVar(1, p[1] ?? 0)));
      }
    }, onDone: down, onError: (_) => down());
  }

  void key(int code) {
    if (!ready || c == null) return;
    c!.send(fBytes(10, [...fVar(1, code), ...fVar(2, 3)]));
    HapticFeedback.lightImpact();
  }

  void close() {
    ready = false;
    c?.close();
    c = null;
  }
}

// ---------- UI ----------
void main() => runApp(const MaterialApp(
    debugShowCheckedModeBanner: false, home: Home()));

class Home extends StatefulWidget {
  const Home({super.key});
  @override
  State<Home> createState() => _HomeState();
}

class _HomeState extends State<Home> {
  final ipCtl = TextEditingController();
  final pinCtl = TextEditingController();
  final remote = Remote();
  Identity? id;
  Pairing? pairing;
  bool paired = false, busy = false, connected = false;
  String msg = '';

  @override
  void initState() {
    super.initState();
    remote.onState = (v) {
      if (mounted) setState(() => connected = v);
    };
    _init();
  }

  Future<void> _init() async {
    setState(() {
      busy = true;
      msg = 'Preparing...';
    });
    await Future.delayed(const Duration(milliseconds: 100));
    id = await Identity.load();
    final p = await SharedPreferences.getInstance();
    ipCtl.text = p.getString('ip') ?? '';
    paired = p.getBool('paired') ?? false;
    setState(() {
      busy = false;
      msg = '';
    });
    if (paired) _connect();
  }

  Future<void> _connect() async {
    try {
      await remote.connect(ipCtl.text.trim(), id!);
    } catch (e) {
      if (mounted) setState(() => msg = 'Cannot connect: $e');
    }
  }

  Future<void> _startPair() async {
    setState(() {
      busy = true;
      msg = '';
    });
    try {
      pairing = await Pairing.start(ipCtl.text.trim(), id!);
      msg = 'Enter the code shown on TV';
    } catch (e) {
      msg = 'Error: $e';
    }
    setState(() => busy = false);
  }

  Future<void> _finishPair() async {
    setState(() => busy = true);
    try {
      await pairing!.finish(pinCtl.text);
      final p = await SharedPreferences.getInstance();
      await p.setString('ip', ipCtl.text.trim());
      await p.setBool('paired', true);
      pairing = null;
      paired = true;
      msg = '';
      _connect();
    } catch (e) {
      msg = 'Error: $e';
    }
    setState(() => busy = false);
  }

  Future<void> _press(int k) async {
    if (!remote.ready) {
      await _connect();
      await Future.delayed(const Duration(milliseconds: 800));
    }
    remote.key(k);
  }

  Widget b(IconData i, int k, {double s = 72}) => Padding(
        padding: const EdgeInsets.all(6),
        child: SizedBox(
          width: s,
          height: s,
          child: FilledButton.tonal(
            style: FilledButton.styleFrom(
                shape: const CircleBorder(), padding: EdgeInsets.zero),
            onPressed: () => _press(k),
            child: Icon(i, size: s * .45),
          ),
        ),
      );

  Widget get gap => const SizedBox(width: 84, height: 84);

  Widget pairView() => Padding(
        padding: const EdgeInsets.all(24),
        child: Column(mainAxisAlignment: MainAxisAlignment.center, children: [
          const Text('Pair with TV box',
              style: TextStyle(fontSize: 22, fontWeight: FontWeight.bold)),
          const SizedBox(height: 16),
          TextField(
              controller: ipCtl,
              keyboardType: TextInputType.number,
              decoration: const InputDecoration(
                  labelText: 'Mi Box IP (e.g. 192.168.1.20)',
                  border: OutlineInputBorder())),
          const SizedBox(height: 12),
          if (pairing == null)
            FilledButton(
                onPressed: busy ? null : _startPair, child: const Text('Pair'))
          else ...[
            TextField(
                controller: pinCtl,
                textCapitalization: TextCapitalization.characters,
                decoration: const InputDecoration(
                    labelText: 'Code on TV', border: OutlineInputBorder())),
            const SizedBox(height: 12),
            FilledButton(
                onPressed: busy ? null : _finishPair,
                child: const Text('Confirm')),
          ],
          const SizedBox(height: 12),
          Text(msg),
        ]),
      );

  Widget remoteView() => SafeArea(
        child: Column(children: [
          Row(mainAxisAlignment: MainAxisAlignment.spaceBetween, children: [
            Padding(
              padding: const EdgeInsets.all(12),
              child: Text(connected ? '● Connected' : '○ Not connected',
                  style: TextStyle(
                      color: connected ? Colors.green : Colors.red)),
            ),
            IconButton(
                icon: const Icon(Icons.settings),
                onPressed: () async {
                  remote.close();
                  final p = await SharedPreferences.getInstance();
                  await p.setBool('paired', false);
                  setState(() => paired = false);
                }),
          ]),
          if (msg.isNotEmpty) Text(msg, style: const TextStyle(fontSize: 12)),
          const Spacer(),
          Row(mainAxisAlignment: MainAxisAlignment.center, children: [
            b(Icons.power_settings_new, 26),
            b(Icons.home, 3),
            b(Icons.arrow_back, 4),
          ]),
          Row(mainAxisAlignment: MainAxisAlignment.center,
              children: [gap, b(Icons.keyboard_arrow_up, 19), gap]),
          Row(mainAxisAlignment: MainAxisAlignment.center, children: [
            b(Icons.keyboard_arrow_left, 21),
            b(Icons.circle, 23),
            b(Icons.keyboard_arrow_right, 22),
          ]),
          Row(mainAxisAlignment: MainAxisAlignment.center,
              children: [gap, b(Icons.keyboard_arrow_down, 20), gap]),
          const SizedBox(height: 12),
          Row(mainAxisAlignment: MainAxisAlignment.center, children: [
            b(Icons.volume_down, 25, s: 60),
            b(Icons.volume_off, 164, s: 60),
            b(Icons.volume_up, 24, s: 60),
            b(Icons.play_arrow, 85, s: 60),
          ]),
          const Spacer(),
        ]),
      );

  @override
  Widget build(BuildContext context) => Scaffold(
        body: busy && id == null
            ? Center(child: Text(msg))
            : (paired ? remoteView() : SafeArea(child: pairView())),
      );
}
