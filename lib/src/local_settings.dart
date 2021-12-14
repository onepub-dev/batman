import 'package:dcli/dcli.dart';
import 'package:dcli/docker.dart';
import 'package:settings_yaml/settings_yaml.dart';
import 'package:yaml/yaml.dart';

import 'log.dart';

class LocalSettings {
  factory LocalSettings() {
    if (_self == null) {
      LocalSettings.load();
    }
    return _self!;
  }

  factory LocalSettings.load() {
    if (_self != null) {
      return _self!;
    }

    if (exists(pathToLocalSettings)) {
      try {
        settings = SettingsYaml.load(pathToSettings: pathToLocalSettings);
        hasLocalSettings = true;
      } on YamlException catch (e) {
        logerr(red('Failed to load rules from $pathToLocalSettings'));
        logerr(red(e.toString()));
        rethrow;
      } on SettingsYamlException catch (e) {
        logerr(red('Failed to load rules from $pathToLocalSettings'));
        logerr(red(e.message));
        rethrow;
      }
    } else {
      settings =
          SettingsYaml.fromString(content: '', filePath: 'settings.yaml');
    }
    return _self = LocalSettings._internal();
  }

  LocalSettings._internal();

  static late final SettingsYaml settings;
  static bool hasLocalSettings = false;

  static const String filename = 'settings.yaml';

  static late final String pathToLocalSettings =
      join(DartScript.self.pathToScriptDirectory, filename);

  static LocalSettings? _self;

  String? _rulePath;

  /// Path to the rule.yaml file.
  String get rulePath => _rulePath ?? _pathToRuleYaml;

  set rulePath(String rulePath) {
    settings['rule_path'] = rulePath;

    _rulePath = rulePath;
  }

  String get _pathToRuleYaml {
    late final String path;

    if (hasLocalSettings) {
      final rulePath = settings.asString('rule_path');
      if (rulePath.isEmpty) {
        throw SettingsYamlException(
            'settings.yaml found in $pathToLocalSettings '
            'but a value for the expected rule_path key was not found');
      }
      path = rulePath;
    } else {
      path = join(HOME, Shell.current.loggedInUser, '.batman');
    }
    return truepath(path);
  }

  void save() {
    settings.save();
  }

  /// name of the package rule.yaml file appropriate for the target platform.
  String get packedRuleYaml {
    late final String path;
    if (DockerShell.inDocker) {
      path = 'docker_batman.yaml';
    } else {
      path = 'local_batman.yaml';
    }
    return path;
  }
}
