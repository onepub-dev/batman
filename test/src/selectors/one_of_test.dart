import 'package:batman/src/rules/risk.dart';
import 'package:batman/src/rules/rules.dart';
import 'package:batman/src/rules/selectors/selector.dart';
import 'package:dcli/dcli.dart' hide equals;
import 'package:settings_yaml/settings_yaml.dart';
import 'package:test/test.dart';

void main() {
  test('one_of with continue', () async {
    final ruleDef = '''
log_audits:
  rules:
    - rule:
      name: locker
      selectors: 
      - selector:
        description: Locker Key
        type: one_of
        match: ["Locker", "Key"]
        exclude: ["Note"]
        risk: high
        
''';

    withTempFile((path) {
      var settings = SettingsYaml.fromString(content: ruleDef, filePath: path);

      final rules = Rules.fromMap(settings);

      final rule = rules.rules.first;
      

      final oneOf = rule.selectors.selectors.first;

      expect(oneOf, isA<OneOf>());
      expect(oneOf.risk, equals(Risk.high));
      if (oneOf is OneOf) {
        expect(oneOf.getType(), equals('one_of'));
        expect(oneOf.description, equals('Locker Key'));
        expect(oneOf.match, orderedEquals(<String>['Locker', 'Key']));
        expect(oneOf.exclude, orderedEquals(<String>['Note']));
        expect(oneOf.terminate, isFalse);

        expect(oneOf.matches('Locker'), Selection.matchContinue);
        expect(oneOf.matches('Key'), Selection.matchContinue);
        expect(oneOf.matches('Nocker'), Selection.nomatch);
        expect(oneOf.matches('Locker Key'), Selection.matchContinue);
        expect(oneOf.matches('Locker Key Note'), Selection.nomatch);
      }
    });
  });

  test('one_of with terminate', () async {
    final ruleDefs = '''
log_audits:
  rules:
    - rule:
      name: locker
      selectors: 
      - selector:
        description: Locker Key
        type: one_of
        match: ["Locker", "Key"]
        exclude: ["Note"]
        continue: false
        risk: high
''';

    withTempFile((path) {
      var settings = SettingsYaml.fromString(content: ruleDefs, filePath: path);

      final rules = Rules.fromMap(settings);

      final rule = rules.rules.first;

      final oneOf = rule.selectors.selectors.first;

      expect(oneOf, isA<OneOf>());
      expect(oneOf.risk, equals(Risk.high));

      if (oneOf is OneOf) {
        expect(oneOf.getType(), equals('one_of'));
        expect(oneOf.description, equals('Locker Key'));
        expect(oneOf.match, orderedEquals(<String>['Locker', 'Key']));
        expect(oneOf.exclude, orderedEquals(<String>['Note']));
        expect(oneOf.terminate, isTrue);

        expect(oneOf.matches('Locker'), Selection.matchTerminate);
        expect(oneOf.matches('Key'), Selection.matchTerminate);
        expect(oneOf.matches('Nocker'), Selection.nomatch);
        expect(oneOf.matches('Locker Key'), Selection.matchTerminate);
        expect(oneOf.matches('Locker Key Note'), Selection.nomatch);
      }
    });
  });
}
