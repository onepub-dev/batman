/* Copyright (C) S. Brett Sutton - All Rights Reserved
 * Unauthorized copying of this file, via any medium is strictly prohibited
 * Proprietary and confidential
 * Written by Brett Sutton <bsutton@onepub.dev>, Jan 2022
 */

@Timeout(Duration(minutes: 30))
library;

import 'package:batman/batman.dart';
import 'package:dcli/dcli.dart' hide run;
import 'package:test/test.dart';

void main() {
  setUp(() {
    env['RULE_PATH'] = 'test/test_rules.yaml';
  });
  test('install ...', () async {
    await run(['install']);
  });

  test('doctor ...', () async {
    await run(['doctor']);
  });

  test('baseline ...', () async {
    await run(['baseline', '--insecure']);
    print('completed baseline');
  });

  test('invalid args ...', () async {
    await run(['baseline', '--docker']);
    print('completed baseline');
  });

  test('integrity ...', () async {
    await run(['integrity', '--insecure', '--count']);
  });

  test('integrity double run', () async {
    await run(['integrity', '--insecure', '--count']);
    await run(['integrity', '--insecure', '--count']);
  });

  test('cron ...', () async {
    await run(['cron', '--insecure', '1 * * * * ']);
  }, skip: true);

  test('logs ...', () async {
    await run(['logs', '--insecure']);
  });

  test('log njcontact', () async {
    await run([
      'log',
      '--insecure',
      '--name=frequency',
      '--path=test/sample_logs/njcontact.log'
    ]);
  });

  test('log credit cards by rule', () async {
    await run([
      'log',
      '--insecure',
      '--rule=creditcard',
      '--path=test/sample_logs/creditcards.log'
    ]);
  });

  test('log credit cards by logsource', () async {
    await run([
      'log',
      '--insecure',
      '--name=njcontact',
      '--path=test/sample_logs/creditcards.log'
    ]);
  });
}
