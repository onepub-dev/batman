@Timeout(Duration(minutes: 30))
import 'package:batman/src/entry_point.dart';
import 'package:dcli/dcli.dart' hide run, equals;
import 'package:test/test.dart';

void main() {
  test('install ...', () {
    run(['install']);
  });

  test('baseline ...', () {
    env['RULE_PATH'] = '$HOME/.batman/rules.yaml';
    run(['baseline', '--insecure', '--count']);
  });

  test('integrity ...', () {
    run(['integrity', '--insecure', '--count']);
  });

  test('cron ...', () {
    run(['cron', '--insecure', '1 * * * * ']);
  });

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

  test('rules ...', () {
    run(['rules']);
  });
}
