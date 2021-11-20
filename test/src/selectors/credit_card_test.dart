import 'package:dcli/dcli.dart' hide equals;
import 'package:pci_file_monitor/src/selectors/selector.dart';
import 'package:settings_yaml/settings_yaml.dart';
import 'package:test/test.dart';

void main() {
  test('creditcard with continue', () async {
    final rules = '''
log_audits:
  log_sources:
  - log_source:
    selectors: 
    - selector:
      description: A credit card was detected in a log file
      type: creditcard
      risk: critical
''';

    withTempFile((path) {
      var settings = SettingsYaml.fromString(content: rules, filePath: path);

      final creditCard = CreditCard.fromMap(settings,
          'log_audits.log_sources.log_source[0].selectors.selector[0]');

      expect(creditCard.getType(), equals('creditcard'));
      expect(creditCard.description,
          equals('A credit card was detected in a log file'));
      expect(creditCard.risk, equals(Risk.critical));
      expect(creditCard.terminate, isFalse);

      expect(creditCard.matches('4111111111111111'), Selection.matchContinue);
      expect(
          creditCard.matches('41111111111111114'), Selection.nomatch);
      expect(creditCard.matches('Locker Key'), Selection.nomatch);
    });
  });

  test('creditcard with terminate', () async {
    final rules = '''
log_audits:
  log_sources:
  - log_source:
    selectors: 
    - selector:
      description: A credit card was detected in a log file
      type: creditcard
      risk: critical
      continue: false
''';

    withTempFile((path) {
      var settings = SettingsYaml.fromString(content: rules, filePath: path);

      final creditCard = CreditCard.fromMap(settings,
          'log_audits.log_sources.log_source[0].selectors.selector[0]');

      expect(creditCard.getType(), equals('creditcard'));
      expect(creditCard.description,
          equals('A credit card was detected in a log file'));
      expect(creditCard.risk, equals(Risk.critical));
      expect(creditCard.terminate, isTrue);

      expect(creditCard.matches('4111111111111111'), Selection.matchTerminate);
      expect(
          creditCard.matches('41111111111111114'), Selection.nomatch);
      expect(creditCard.matches('Locker Key'), Selection.nomatch);
    });
  });
}
