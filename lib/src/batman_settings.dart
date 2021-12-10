import 'package:dcli/dcli.dart';
import 'package:meta/meta.dart';
import 'package:settings_yaml/settings_yaml.dart';
import 'package:yaml/yaml.dart';

import 'log.dart';
import 'rules/batman_yaml_logger.dart';
import 'rules/log_audits.dart';
import 'settings_yaml_rules.dart';

class BatmanSettings {
  factory BatmanSettings() {
    if (_self == null) {
      BatmanSettings.load();
    }
    return _self!;
  }

  factory BatmanSettings.load({bool showWarnings = false}) {
    if (_self != null) {
      return _self!;
    }

    try {
      final settings = SettingsYaml.load(pathToSettings: pathToRules);
      _self =
          BatmanSettings.loadFromSettings(settings, showWarnings: showWarnings);
      return _self!;
    } on YamlException catch (e) {
      logerr(red('Failed to load rules from $pathToRules'));
      logerr(red(e.toString()));
      rethrow;
    } on RulesException catch (e) {
      logerr(red('Failed to load rules from $pathToRules'));
      logerr(red(e.message));
      rethrow;
    }
  }

  @visibleForTesting
  BatmanSettings.loadFromSettings(this.settings, {required this.showWarnings}) {
    BatmanYamlLogger().info(() => 'loading rules.yaml from $pathToRules');

    BatmanYamlLogger()
        .info(() => 'Found ${entities.length} paths to be scanned');
    BatmanYamlLogger().info(() => entities.join('\n'));
    BatmanYamlLogger()
        .info(() => 'Found ${exclusions.length} paths to be excluded');
    BatmanYamlLogger().info(() => exclusions.join('\n'));

    logAudits = LogAudits.fromSettings(settings);
  }
  static BatmanSettings? _self;

  bool showWarnings;

  late final LogAudits logAudits;

  late final SettingsYaml settings;

  /// Path to the .batman settings directory
  static late final String pathToSettingsDir =
      join(rootPath, 'home', Shell.current.loggedInUser, '.batman');

  static late final String defaultPathToDb =
      join(BatmanSettings.pathToSettingsDir, 'hive');

  /// Path to the batman rules.yaml file.
  static late final String pathToRules =
      env['RULE_PATH'] ?? join(pathToSettingsDir, 'rules.yaml');

  late final bool reportOnSuccess =
      settings.asBool('report_on_success', defaultValue: false);

  String? _pathToDb;

  /// Path to the file integrity hashes
  set pathToDb(String pathToDb) => _pathToDb = pathToDb;

  /// Path to the file integrity hashes
  String get pathToDb => _pathToDb ??= settings.asString('db_path',
      defaultValue: join(pathToSettingsDir, 'hive'));

  /// Returns the list of files/directories to be scanned and baselined
  List<String> get entities =>
      settings.ruleAsStringList('file_integrity', 'entities', <String>[]);

  /// The maximum no. of bytes to be scanned from a file.
  late final int scanByteLimit =
      settings.asInt('file_integrity.scan_byte_limit', defaultValue: 25000000);

  /// Returns the list of files/directories to be excluded from the
  /// scan and baseline.
  List<String> get exclusions =>
      settings.ruleAsStringList('file_integrity', 'exclusions', <String>[]);

  /// If true then we will send an email if the scan fails
  bool get sendEmailOnFail =>
      settings.asBool('send_email_on_fail', defaultValue: false);

  /// If true then we will send an email if the scan succeeds
  bool get sendEmailOnSuccess =>
      settings.asBool('send_email_on_success', defaultValue: false);

  String get emailServer =>
      settings.asString('email_server_host', defaultValue: 'localhost');
  int get emailPort => settings.asInt('email_server_port', defaultValue: 25);

  /// The email address used as the 'from' email when sending any emails
  String get emailFromAddress => settings.asString('email_from_address');

  /// The email address to send failed scans to
  String get emailFailToAddress => settings.asString('email_fail_to_address');

  /// The email address to send successful scans to.
  /// If not specified we us the [emailFailToAddress]
  String get emailSuccessToAddress =>
      settings.asString('email_success_to_address');

  bool excluded(String path) {
    if (path.startsWith(pathToSettingsDir)) {
      return true;
    }
    for (final exclusion in exclusions) {
      if (path.startsWith(exclusion)) {
        return true;
      }
    }
    return false;
  }
}

class RulesException implements Exception {
  RulesException(this.message);
  String message;

  @override
  String toString() => message;
}
