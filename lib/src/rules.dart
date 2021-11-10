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

  List<String> get entities => settings.asStringList('entities');

  List<String> get exclusions => settings.asStringList('exclusions');
}
