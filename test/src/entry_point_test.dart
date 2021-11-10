@Timeout(Duration(minutes: 30))
import 'package:pci_file_monitor/src/entry_point.dart';
import 'package:test/test.dart';

void main() {
  test('entry point ...', () async {
    run(['install']);
  });

  test('entry point ...', () async {
    run(['baseline', '--insecure']);
  });
}
