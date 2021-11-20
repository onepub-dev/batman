import 'package:dcli/dcli.dart' hide equals;
import 'package:pci_file_monitor/src/selectors/selector.dart';
import 'package:settings_yaml/settings_yaml.dart';
import 'package:test/test.dart';

void main() {
  test('one_of with continue', () async {
    final rules = '''
log_audits:
  log_sources:
  - log_source:
    selectors: 
    - selector:
      description: Locker Key
      type: one_of
      match: ["Locker", "Key"]
      exclude: ["Note"]
      risk: high
''';

    withTempFile((path) {
      var settings = SettingsYaml.fromString(content: rules, filePath: path);

      final oneOf = OneOf.fromMap(settings,
          'log_audits.log_sources.log_source[0].selectors.selector[0]');

      expect(oneOf.getType(), equals('one_of'));
      expect(oneOf.description, equals('Locker Key'));
      expect(oneOf.match, orderedEquals(<String>['Locker', 'Key']));
      expect(oneOf.exclude, orderedEquals(<String>['Note']));
      expect(oneOf.risk, equals(Risk.high));
      expect(oneOf.terminate, isFalse);

      expect(oneOf.matches('Locker'), Selection.matchContinue);
      expect(oneOf.matches('Key'), Selection.matchContinue);
      expect(oneOf.matches('Nocker'), Selection.nomatch);
      expect(oneOf.matches('Locker Key'), Selection.matchContinue);
      expect(oneOf.matches('Locker Key Note'), Selection.nomatch);
    });
  });

  test('one_of with termiante', () async {
    final rules = '''
log_audits:
  log_sources:
  - log_source:
    selectors: 
    - selector:
      description: Locker Key
      type: one_of
      match: ["Locker", "Key"]
      exclude: ["Note"]
      risk: high
      continue: false
''';

    withTempFile((path) {
      var settings = SettingsYaml.fromString(content: rules, filePath: path);

      final oneOf = OneOf.fromMap(settings,
          'log_audits.log_sources.log_source[0].selectors.selector[0]');

      expect(oneOf.getType(), equals('one_of'));
      expect(oneOf.description, equals('Locker Key'));
      expect(oneOf.match, orderedEquals(<String>['Locker', 'Key']));
      expect(oneOf.exclude, orderedEquals(<String>['Note']));
      expect(oneOf.risk, equals(Risk.high));
      expect(oneOf.terminate, isTrue);

      expect(oneOf.matches('Locker'), Selection.matchTerminate);
      expect(oneOf.matches('Key'), Selection.matchTerminate);
      expect(oneOf.matches('Nocker'), Selection.nomatch);
      expect(oneOf.matches('Locker Key'), Selection.matchTerminate);
      expect(oneOf.matches('Locker Key Note'), Selection.nomatch);
    });
  });
}
