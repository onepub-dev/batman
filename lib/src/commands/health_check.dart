import 'dart:async';
import 'dart:io';

import 'package:args/command_runner.dart';
import 'package:dcli/dcli.dart';
import '../log_source/log_source.dart';
import '../selectors/selector.dart';

import '../rules.dart';

class HealthCheckCommand extends Command<void> {
  @override
  void run() {
    _logCheck();
  }

  @override
  String get description =>
      'Scans system logs looking for errors and malicious intent';

  @override
  String get name => 'health';
}

void _logCheck() {
  final rules = Rules.load();
  final logSources = rules.logAudits;
  final globalSelectors = logSources.globalSelectors;
  for (final source in logSources.sources) {
    var selectors = <Selector>[];

    selectors.addAll(globalSelectors);
    if (source.exists) {
      _runChecks(source: source, selectors: selectors);
    }
  }
}

/// Runs log checks by scanning the lines output from the given [container].
/// Constrains the output to [top] errors so we don't overwhelm the user.
void _runChecks({
  required LogSource source,
  required List<Selector> selectors,
}) {
  final analyser = source.analyser;

  print(
      'Processing LogSource of type ${source.getType()} : ${source.description}');

  final stream = source.stream();
  final logStatsMap = <String, LogStats>{};
  var lineCounter = 0;
  var restartAt = '';

  /// process the log file.
  late final StreamSubscription<String> sub;
  sub = stream.listen((line) {
    sub.pause();
    lineCounter++;

    if (lineCounter % 10000 == 0) {
      stdout.write('.');
    }
    analyser.process(line);
    if (analyser.reset) {
      logStatsMap.clear();
      lineCounter = 0;
      restartAt = orange(line);
    }

    for (final selector in selectors) {
      final selection = selector.matches(line);
      if (selection == Selection.nomatch) continue;

      /// the selector matched the line.
      var key = source.getKey(line, selector);

      var logStats = logStatsMap[key];
      if (logStats == null) {
        logStats = LogStats(key, selector.description);
        logStatsMap[key] = logStats;
      }

      /// log an example line.
      logStats.addExample(source.tidyLine(line));

      if (selection == Selection.matchTerminate) break;
    }
    sub.resume();
  });

  waitForEx(sub.asFuture<void>());

  if (restartAt.isNotEmpty) {
    print('');
    print(restartAt);
    print(orange('Encountered reset point in logs, discarded prior logs'));
    print('');
  }
  print('Checked $lineCounter log lines');

  printStats(logStatsMap, source);
  print('');
}

void printStats(Map<String, LogStats> logStatsMap, LogSource source) {
  final sorted = <LogStats>[];
  for (final logStats in logStatsMap.values) {
    sorted.add(logStats);
  }

  sorted.sort((a, b) {
    return b.count - a.count;
  });

  var ctr = 0;
  for (final logStats in sorted) {
    ctr++;
    if (ctr > source.top) {
      break;
    }
    print(
        '${logStats.description} (${logStats.count})\n\t  FIRST ${logStats.firstExample}\n\t  LAST  ${logStats.lastExample}');
    print('');
  }
  if (logStatsMap.isEmpty) {
    print(green('No problems found'));
  }
}

class LogStats {
  int count = 0;
  String firstExample = '';
  String lastExample = '';
  String description;

  String key;

  LogStats(this.key, this.description);

  void addExample(String example) {
    if (firstExample.isEmpty) {
      firstExample = example;
    } else {
      lastExample = example;
    }
    count++;
  }
}
