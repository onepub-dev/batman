import 'package:batman/src/rules/risk.dart';
import 'package:batman/src/rules/rules.dart';
import 'package:batman/src/rules/selectors/selector.dart';
import 'package:dcli/dcli.dart' hide equals;
import 'package:settings_yaml/settings_yaml.dart';
import 'package:test/test.dart';

void main() {
  test('creditcard with continue', () {
    const ruleDef = '''
log_audits:
  rules:
    - rule:
      name: locker
      
      selectors: 
      - selector:
        description: A credit card was detected in a log file
        type: creditcard
        risk: critical
        
''';

    withTempFile((path) {
      final settings =
          SettingsYaml.fromString(content: ruleDef, filePath: path);

      final rules = Rules.fromMap(settings);
      final rule = rules.rules.first;

      final creditCard = rule.selectors.selectors.first;

      expect(creditCard, isA<CreditCard>());
      expect(creditCard.risk, equals(Risk.critical));
      if (creditCard is CreditCard) {
        expect(creditCard.getType(), equals('creditcard'));
        expect(creditCard.description,
            equals('A credit card was detected in a log file'));

        expect(creditCard.terminate, isFalse);

        expect(creditCard.matches('4111111111111111'), Selection.matchContinue);
        expect(creditCard.matches('41111111111111114'), Selection.nomatch);
        expect(creditCard.matches('Locker Key'), Selection.nomatch);
      }
    });
  });

  test('creditcard with terminate', () {
    const ruleDef = '''
log_audits:
  rules:
    - rule:
      name: locker
      selectors: 
      - selector:
        description: A credit card was detected in a log file
        type: creditcard
        continue: false
        risk: critical
''';

    withTempFile((path) {
      final settings =
          SettingsYaml.fromString(content: ruleDef, filePath: path);

      final rules = Rules.fromMap(settings);
      final rule = rules.rules.first;

      final creditCard = rule.selectors.selectors.first;
      expect(creditCard.risk, equals(Risk.critical));

      expect(creditCard, isA<CreditCard>());
      expect(creditCard.getType(), equals('creditcard'));
      expect(creditCard.description,
          equals('A credit card was detected in a log file'));

      expect(creditCard.terminate, isTrue);

      expect(creditCard.matches('4111111111111111'), Selection.matchTerminate);
      expect(creditCard.matches('41111111111111114'), Selection.nomatch);
      expect(creditCard.matches('Locker Key'), Selection.nomatch);
    });
  });
}
