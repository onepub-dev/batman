import 'package:batman/src/commands/logs.dart';
import 'package:test/test.dart';

void main() {
  test('health check ...', () async {
    LogsCommand().run();
  });
}
