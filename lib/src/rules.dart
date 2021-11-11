import 'package:dcli/dcli.dart';
import 'package:settings_yaml/settings_yaml.dart';

class Rules {
  Rules.load() {
    settings = SettingsYaml.load(pathToSettings: pathToRules);
  }
  late final SettingsYaml settings;

  static late final String pathToSettings =
      join(rootPath, 'home', Shell.current.loggedInUser, '.pcifim');
  static late final String pathToRules = join(pathToSettings, 'rules.yaml');
  static late final String pathToHashes = join(pathToSettings, 'hashes');

  /// Returns the list of files/directories to be scanned and baselined
  List<String> get entities => settings.asStringList('entities');

  /// Returns the list of files/directories to be excluded from the
  /// scan and baseline.
  List<String> get exclusions => settings.asStringList('exclusions');

  /// If true then we will send an email if the scan fails
  bool get sendEmailOnFail =>
      settings.asBool('sendEmailOnFail', defaultValue: false);

  /// If true then we will send an email if the scan succeeds
  bool get sendEmailOnSuccess =>
      settings.asBool('sendEmailOnSuccess', defaultValue: false);

  String get emailServer =>
      settings.asString('emailServerFQDN', defaultValue: 'localhost');
  int get emailPort => settings.asInt('emailServerPort', defaultValue: 25);

  /// The email address used as the 'from' email when sending any emails
  String get emailFromAddress => settings.asString('emailFromAddress');

  /// The email address to send failed scans to
  String get emailFailToAddress => settings.asString('emailFailToAddress');

  /// The email address to send successful scans to.
  /// If not specified we us the [emailFailToAddress]
  String get emailSuccessToAddress =>
      settings.asString('emailSuccessToAddress');
}
