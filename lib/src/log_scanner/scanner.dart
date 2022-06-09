/* Copyright (C) S. Brett Sutton - All Rights Reserved
 * Unauthorized copying of this file, via any medium is strictly prohibited
 * Proprietary and confidential
 * Written by Brett Sutton <bsutton@onepub.dev>, Jan 2022
 */

import 'dart:async';

import 'package:dcli/dcli.dart';

import '../batman_settings.dart';
import '../log.dart';
import '../log_scanner/log_sources/log_source.dart';

/// Scans logs for problems.

void scanOneLog(String name, String? path,
    {required bool secureMode, required bool quiet}) {
  withTempFile((alteredFiles) {
    Shell.current.withPrivileges(() {
      final rules = BatmanSettings.load();
      final logSources = rules.logAudits;
      var found = false;
      for (final source in logSources.sources) {
        if (source.name == name) {
          // the exists of path has already been checked (if passed)
          if (source.exists || path != null) {
            found = true;
            scanLogSource(logSource: source, path: path);
          }
        }
      }
      if (found == false) {
        logerr('A log_source with name $name was not found');
      }
    }, allowUnprivileged: true);

    if (!quiet) {
      log('');
    }
  });
}

/// Runs log checks by scanning the lines output from the given [logSource].
void scanLogSource({
  required LogSource logSource,
  String? path,
}) {
  final analyser = logSource.analyser;
  if (path != null) {
    logSource.overrideSource = path;
  }

  loginfo('Processing LogSource: ${logSource.description} : '
      'source ${logSource.source}');

  final stream = logSource.stream();
  var lineCounter = 0;

  /// process the log file.
  late final StreamSubscription<String> sub;
  sub = stream.listen((line) {
    sub.pause();
    lineCounter++;

    if (lineCounter % 10000 == 0) {
      echo('.');
    }

    line = logSource.preProcessLine(line);

    /// we give the analyser a chance to look at every line.
    analyser.preProcessLine(logSource, line, lineCounter);
    final matches = analyser.testForMatches(logSource, line, lineCounter);

    line = logSource.tidyLine(line);

    for (final match in matches) {
      line = match.rule.sanitiseLine(line);
      analyser.processMatch(
          logSource, match.rule, match.selector, line, lineCounter);
    }
    sub.resume();
  });

  /// Wait for the stream to end
  waitForEx(sub.asFuture<void>());
  sub.cancel();

  final matchCount = analyser.matchCount;
  loginfo('');
  loginfo('Checked $lineCounter log lines, matched: $matchCount');
  if (matchCount == 0) {
    loginfo(green('No problems found.'));
  } else {
    loginfo(red('Found $matchCount problems.'));
  }

  final sb = StringBuffer();
  if (matchCount != 0) {
    loginfo(analyser.prepareReport(logSource, sb).toString());
  }

  loginfo('');
}
