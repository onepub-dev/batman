@Timeout(Duration(minutes: 30))
import 'package:batman/batman.dart';
import 'package:dcli/dcli.dart' hide run, equals;
import 'package:test/test.dart';

void main() {
  setUp(() {
    env['RULE_PATH'] = 'test/test_rules.yaml';
  });
  test('install ...', () {
    run(['install']);
  });

  test('doctor ...', () {
    run(['doctor']);
  });

  test('baseline ...', () {
    run(['baseline', '--insecure']);
    print('completed baseline');
  });

  test('integrity ...', () {
    run(['integrity', '--insecure', '--count']);
  });

  test('integrity double run', () {
    run(['integrity', '--insecure', '--count']);
    run(['integrity', '--insecure', '--count']);
  });

  test('cron ...', () {
    run(['cron', '--insecure', '1 * * * * ']);
  }, skip: true);

  test('logs ...', () {
    run(['logs', '--insecure']);
  });

  test('log njcontact', () {
    run([
      'log',
      '--insecure',
      '--name=frequency',
      '--path=test/sample_logs/njcontact.log'
    ]);
  });

  test('log credit cards by rule', () {
    run([
      'log',
      '--insecure',
      '--rule=creditcard',
      '--path=test/sample_logs/creditcards.log'
    ]);
  });

  test('log credit cards by logsource', () {
    run([
      'log',
      '--insecure',
      '--name=njcontact',
      '--path=test/sample_logs/creditcards.log'
    ]);
  });
}
