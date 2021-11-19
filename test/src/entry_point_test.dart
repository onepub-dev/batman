@Timeout(Duration(minutes: 30))
import 'package:pci_file_monitor/src/entry_point.dart';
import 'package:test/test.dart';

void main() {
  test('install ...', () async {
    run(['install']);
  });

  test('baseline ...', () async {
    run(['baseline', '--insecure']);
  });

  test('cron ...', () async {
    run(['cron', '--insecure', '1 * * * * ']);
  });
}
