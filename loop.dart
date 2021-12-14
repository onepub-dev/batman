import 'package:dcli/dcli.dart';

void main() {
  for (var i = 0; i < 10000; i++) {
    '/tmp/f9dbeede-fbbc-4c93-9532-9f2f9261df73.tmp'.append('hi $i');
  }
}
