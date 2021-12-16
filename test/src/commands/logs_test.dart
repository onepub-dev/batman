import 'package:batman/src/commands/logs.dart';
import 'package:batman/src/parsed_args.dart';
import 'package:test/test.dart';

void main() {
  test('health check ...', () {
    ParsedArgs.withArgs(['--insecure']);
    LogsCommand().run();
  });
}
