import 'dart:async';
import 'dart:io';

import 'package:args/command_runner.dart';
import 'package:dcli/dcli.dart';
import '../log_source/log_source.dart';
import '../selectors/selector.dart';
import 'package:system_info/system_info.dart';

class CommandSystemHealth extends Command<void> {
  @override
  void run() {
    print('');
    print('');

    final memory = Format.bytesAsReadable(SysInfo.getTotalPhysicalMemory());

    print('Memory: $memory');
  }

  @override
  String get description =>
      'Scans system logs looking for errors and malicious intent';

  @override
  String get name => 'health';
}

//Mar 29 13:40:00 pbx1 30fb154eb68b[1613]: 29 13:40:00,003 AsteriskITScheduler_Worker-2 USER: [INFO] (InDayMigrationJob.java:83) - Checking for recordings...

//Mar 29 13:40:07 pbx1 30fb154eb68b[1613]: 29 13:40:07,252 pool-2-thread-14 USER: [INFO] (StartupMonitorTickets.java:61) - Ticket Monitor Running

//Mar 29 13:40:27 pbx1 30fb154eb68b[1613]: 29 13:40:27,252 pool-2-thread-33 USER: [INFO] (StartupMonitorTickets.java:61) - Ticket Monitor Running

//Mar 29 13:40:47 pbx1 30fb154eb68b[1613]: 29 13:40:47,252 pool-2-thread-48 USER: [INFO] (StartupMonitorTickets.java:61) - Ticket Monitor Running

void _logCheck() {
  // print(red('High Frequency Check...'));
  // var logHandlers = <Selector>[];

  // logHandlers.add(Contains(' ', 'Frequency'));
  // _runChecks(
  //     source: NJContactLogSource( handlers: logHandlers, top: 10);

  // print(red('Known Issues Check...'));
  // logHandlers = <Selector>[];

  // logHandlers.add(Contains('ERROR', 'Errors'));
  // // logHandlers.add(LogHandlerGeneric('WARN', 'Warnings'));
  // logHandlers
  //     .add(Contains('Exception', 'Exceptions', important: true));
  // logHandlers.add(Contains('jvm pause', 'JVM Pause'));
  // logHandlers.add(Contains('Locker', 'Locker'));
  // logHandlers.add(Contains('Slow', 'Slow'));
  // logHandlers.add(Contains(
  //     'Terminating due to java.lang.OutOfMemoryError', 'OutOfMemory',
  //     important: true));

  // logHandlers.add(Contains(
  //     'Unable to save changes (Wrong or no lead)', 'Wrong lead trying to save!',
  //     important: true));

  // _runChecks(source: DockerLogSource('njadmin'), handlers: logHandlers);
}

/// Runs log checks by scanning the lines output from the given [container].
/// Constrains the output to [top] errors so we don't overwhelm the user.
void _runChecks(
    {required LogSource source,
    required List<Selector> handlers,
    int top = 1000}) {
  final logStatsMap = <String, LogStats>{};

  var linesCounter = 0;

  var restartAt = '';

  final stream = source.stream();

  late final StreamSubscription<String> sub;
  sub = stream.listen((line) {
    sub.pause();
    linesCounter++;
    if (linesCounter % 10000 == 0) {
      stdout.write('.');
    }
    if (line.contains('Starting Servlet engine')) {
      // server start, discard all entries before this point

      restartAt = orange(line);

      logStatsMap.clear();
      linesCounter = 0;
    }
    // for (final logHandler in handlers) {
    //   if (logHandler.matches(line)) { //  && !omit(line)
    //     var key = source.getKey(line, logHandler);

    //     var logStats = logStatsMap[key];
    //     if (logStats == null) {
    //       logStats = LogStats(key, logHandler.description);
    //       logStatsMap[key] = logStats;
    //     }
    //     var idx = line.indexOf(':::');
    //     if (idx < 0) {
    //       idx = 0;
    //      }
    //     logStats.addExample(line.substring(idx));
    //    }
    // }
    sub.resume();
  });

  if (restartAt.isNotEmpty) {
    print('');
    print(restartAt);
    print(orange('Encountered tomcat restart in logs, discarding prior logs'));
    print('');
  }
  print('\nChecked $linesCounter log lines');
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
    if (ctr > top) {
      break;
    }
    print(
        '${logStats.description} (${logStats.count})\n\t  FIRST ${logStats.firstExample}\n\t  LAST  ${logStats.lastExample}');
    print('');
  }
}

bool omit(String line) {
  return line.contains('AgiHangupException') ||
      line.contains('Setting logging level to') ||
      line.contains('com.mysql.cj.') ||
      line.contains('RejectedExecutionHandlerImpl') ||
      line.contains('Logs begin at') ||
      line.contains('LoggingOutputStream');
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
