/* Copyright (C) S. Brett Sutton - All Rights Reserved
 * Unauthorized copying of this file, via any medium is strictly prohibited
 * Proprietary and confidential
 * Written by Brett Sutton <bsutton@onepub.dev>, Jan 2022
 */


import 'package:dcli/dcli.dart';
import 'package:settings_yaml/settings_yaml.dart';

import '../../settings_yaml_rules.dart';
import '../analysers/njcontact_analyser.dart';
import '../analysers/source_analyser.dart';
import 'grouped_log_source.dart';

/// Handles logs from a text file
class NJContactLogSource extends GroupedLogSource {
  /// Creates a LogSource that reads from journald
  /// returning any log messages form the passed docker container.
  NJContactLogSource.fromMap(SettingsYaml settings, String location)
      : super.fromMap(settings, location) {
    container = 'njadmin';
    final _trimPrefix = settings.ruleAsString(location, 'trim_prefix', '');
    if (_trimPrefix.isNotEmpty) {
      trimPrefix = RegExp(_trimPrefix);
    } else {
      trimPrefix = null;
    }
  }

  static const type = 'njcontact';
  static const startMessage = 'Starting Servlet engine';

  late final String container;

  /// We will trim the prefix of the line upto and including
  /// [trimPrefix]
  late final RegExp? trimPrefix;

  String? overridePath;

  @override
  Stream<String> stream() {
    var seenStart = false;

    final Stream<String> stream;
    if (overridePath == null) {
      stream =
          "journalctl CONTAINER_NAME=$container --since '1 day ago'".stream();
    } else {
      stream = read(overridePath!).stream;
    }

    return stream.skipWhile((line) {
      if (seenStart) {
        return false;
      }
      if (line.contains(startMessage)) {
        seenStart = true;
      }
      return seenStart;
    });
  }

  @override
  String tidyLine(String line) {
    var idx = 0;
    if (trimPrefix != null) {
      final prefix = trimPrefix!.firstMatch(line)?.group(0) ?? '';
      idx = line.indexOf(prefix);
      if (idx < 0) {
        idx = 0;
      }
      idx += prefix.length;
    }

    return line.substring(idx);
  }

  /// TODO is there a way to check if the journal file exists?
  @override
  bool get exists => true;

  @override
  SourceAnalyser get analyser => NJContactAnalyser();

  @override
  String getType() => type;

  @override
  String get source => overridePath ?? 'journald docker container $container';

  @override
  String preProcessLine(String line) => line;

  @override
  // ignore: avoid_setters_without_getters
  set overrideSource(String path) => overridePath = path;
}
