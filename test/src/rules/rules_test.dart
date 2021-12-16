import 'package:batman/src/rules/risk.dart';
import 'package:batman/src/rules/rules.dart';
import 'package:dcli/dcli.dart' hide equals;
import 'package:settings_yaml/settings_yaml.dart';
import 'package:test/test.dart';

void main() {
  test('contains with terminate', () {
    const ruleDef = '''
log_audits:
  rules:
    - rule:
      name: creditcard
      description: Scans for credit cards 
      selectors:
        - selector:
          type: creditcard
          description: A credit card was detected in a log file
          risk: critical
''';

    withTempFile((path) {
      final settings =
          SettingsYaml.fromString(content: ruleDef, filePath: path);

      final rules = Rules.fromMap(settings);
      expect(rules.rules.length, equals(1));
      final r1 = rules.rules[0];
      expect(r1.name, equals('creditcard'));
      expect(r1.description, equals('Scans for credit cards'));
      final s1 = r1.selectors.selectors.first;
      expect(s1.risk, equals(Risk.critical));

      expect(s1.getType(), equals('creditcard'));
      expect(
          s1.description, equals('A credit card was detected in a log file'));

      expect(s1.terminate, isFalse);

      // expect(contains.matches('Locker'), Selection.matchTerminate);
      // expect(contains.matches('Nocker'), Selection.nomatch);
      // expect(contains.matches('Locker Key'), Selection.nomatch);
      // expect(contains.matches('Locker'), Selection.matchTerminate);
    });
  });
}
