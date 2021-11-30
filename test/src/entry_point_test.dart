@Timeout(Duration(minutes: 30))
import 'package:batman/src/entry_point.dart';
import 'package:test/test.dart';

void main() {
  test('install ...', () async {
    run(['install']);
  });

  test('baseline ...', () async {
    run(['baseline', '--insecure', '--logfile=/var/log/batman.log']);
  });

  test('integrity ...', () async {
    run(['integrity', '--insecure', '--logfile=/var/log/batman.log']);
  });

  test('cron ...', () async {
    run(['cron', '--insecure', '1 * * * * ']);
  });

  test('logs ...', () async {
    run(['logs', '--insecure']);
  });

  test('log njcontact', () async {
    run([
      'log',
      '--insecure',
      '--name=frequency',
      '--path=test/sample_logs/njcontact.log'
    ]);
  });

  test('log credit cards by rule', () async {
    run([
      'log',
      '--insecure',
      '--rule=creditcard',
      '--path=test/sample_logs/creditcards.log'
    ]);
  });

  test('log credit cards by logsource', () async {
    run([
      'log',
      '--insecure',
      '--name=njcontact',
      '--path=test/sample_logs/creditcards.log'
    ]);
  });

  test('rules ...', () async {
    run(['rules']);
  });
}
