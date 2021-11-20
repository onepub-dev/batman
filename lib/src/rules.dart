import 'dart:io';

import 'package:dcli/dcli.dart';
import 'package:meta/meta.dart';
import 'package:settings_yaml/settings_yaml.dart';

import 'log.dart';
import 'log_source/log_audits.dart';

class Rules {
  static Rules? _self;

  factory Rules() => _self!;

  static Rules load({bool showWarnings = false}) {
    if (_self != null) return _self!;

    try {
      final settings = SettingsYaml.load(pathToSettings: pathToRules);
      _self = Rules.loadFromSettings(settings, showWarnings: showWarnings);
      return _self!;
    } on RulesException catch (e) {
      logerr(red('Failed to load rules from $pathToRules'));
      logerr(red(e.message));
      exit(1);
    }
  }

  @visibleForTesting
  Rules.loadFromSettings(this.settings, {required this.showWarnings}) {
    RuleLogger().info(() => 'loading rules.yaml from $pathToRules');

    RuleLogger().info(() => 'Found ${entities.length} paths to be scanned');
    RuleLogger().info(() => entities.join('\n'));
    RuleLogger().info(() => 'Found ${exclusions.length} paths to be excluded');
    RuleLogger().info(() => exclusions.join('\n'));

    logAudits = LogAudits.fromSettings(settings);
  }

  bool showWarnings;

  late final LogAudits logAudits;

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

  bool excluded(String path) {
    if (path.startsWith(pathToSettings)) return true;
    for (final exclusion in exclusions) {
      if (path.startsWith(exclusion)) {
        return true;
      }
    }
    return false;
  }
}

class RuleLogger {
  static late final RuleLogger _self = RuleLogger._internal();

  factory RuleLogger() => _self;

  bool showWarnings = false;

  RuleLogger._internal();

  void warning(String Function() action) {
    if (showWarnings || Settings().isVerbose) {
      log('Warning: ${action()}');
    }
  }

  void info(String Function() action) {
    if (showWarnings || Settings().isVerbose) {
      log('Info: ${action()}');
    }
  }
}

class RulesException implements Exception {
  RulesException(this.message);
  String message;
}
