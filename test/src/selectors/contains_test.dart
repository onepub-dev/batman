import 'package:dcli/dcli.dart' hide equals;
import 'package:pci_file_monitor/src/selectors/selector.dart';
import 'package:settings_yaml/settings_yaml.dart';
import 'package:test/test.dart';

void main() {
  test('contains with continue', () async {
    final rules = '''
log_audits:
  log_sources:
  - log_source:
    selectors: 
    - selector:
      description: Locker
      type: contains
      match: ["Locker"]
      exclude: ["Key"]
      risk: medium
''';

    withTempFile((path) {
      var settings = SettingsYaml.fromString(content: rules, filePath: path);

      final contains = Contains.fromMap(settings,
          'log_audits.log_sources.log_source[0].selectors.selector[0]');

      expect(contains.getType(), equals('contains'));
      expect(contains.description, equals('Locker'));
      expect(contains.insensitive, isFalse);
      expect(contains.match, orderedEquals(<String>['Locker']));
      expect(contains.exclude, orderedEquals(<String>['Key']));
      expect(contains.risk, equals(Risk.medium));
      expect(contains.terminate, isFalse);

      expect(contains.matches('Locker'), Selection.matchContinue);
      expect(contains.matches('Nocker'), Selection.nomatch);
      expect(contains.matches('Locker Key'), Selection.nomatch);
      expect(contains.matches('Locker'), Selection.matchContinue);
    });
  });

  test('contains with terminate', () async {
    final rules = '''
log_audits:
  log_sources:
  - log_source:
    selectors: 
    - selector:
      description: Locker
      type: contains
      continue: false
      match: ["Locker"]
      exclude: ["Key"]
      risk: medium
''';

    withTempFile((path) {
      var settings = SettingsYaml.fromString(content: rules, filePath: path);

      final contains = Contains.fromMap(settings,
          'log_audits.log_sources.log_source[0].selectors.selector[0]');

      expect(contains.getType(), equals('contains'));
      expect(contains.description, equals('Locker'));
      expect(contains.insensitive, isFalse);
      expect(contains.match, orderedEquals(<String>['Locker']));
      expect(contains.exclude, orderedEquals(<String>['Key']));
      expect(contains.risk, equals(Risk.medium));
      expect(contains.terminate, isTrue);

      expect(contains.matches('Locker'), Selection.matchTerminate);
      expect(contains.matches('Nocker'), Selection.nomatch);
      expect(contains.matches('Locker Key'), Selection.nomatch);
      expect(contains.matches('Locker'), Selection.matchTerminate);
    });
  });

  test('contains case-insensitive', () async {
    final rules = '''
log_audits:
  log_sources:
  - log_source:
    selectors: 
    - selector:
      description: Locker
      type: contains
      match: ["Locker"]
      exclude: ["Key"]
      insensitive: true
      risk: none
      continue: false
''';

    withTempFile((path) {
      var settings = SettingsYaml.fromString(content: rules, filePath: path);

      final contains = Contains.fromMap(settings,
          'log_audits.log_sources.log_source[0].selectors.selector[0]');

      expect(contains.getType(), equals('contains'));
      expect(contains.description, equals('Locker'));
      expect(contains.insensitive, isTrue);
      expect(contains.match, orderedEquals(<String>['locker']));
      expect(contains.exclude, orderedEquals(<String>['key']));
      expect(contains.risk, equals(Risk.none));
      expect(contains.terminate, isTrue);

      expect(contains.matches('locker'), Selection.matchTerminate);
      expect(contains.matches('nocker'), Selection.nomatch);
      expect(contains.matches('LOCKER KEY'), Selection.nomatch);
      expect(contains.matches('LOCKER'), Selection.matchTerminate);
    });
  });
}
