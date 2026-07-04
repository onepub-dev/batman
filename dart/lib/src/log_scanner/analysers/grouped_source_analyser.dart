/* Copyright (C) S. Brett Sutton - All Rights Reserved
 * Unauthorized copying of this file, via any medium is strictly prohibited
 * Proprietary and confidential
 * Written by Brett Sutton <bsutton@onepub.dev>, Jan 2022
 */


import 'package:dcli/dcli.dart';

import '../../enum_helper.dart';
import '../../rules/risk.dart';
import '../../rules/rule.dart';
import '../../rules/selectors/selector.dart';
import '../log_sources/log_source.dart';
import 'source_analyser.dart';

/// Code to assist with implementing a source analyser
/// that groups lines from the logs
abstract class GroupedSourceAnalyser implements SourceAnalyser {
  /// Returns a key as a method to link
  /// lines selected out of log source
  /// as being important.
  String getGroup(String line, Selector selector);
}

/// Summary details about lines that have been grouped together
/// by usage of the group_by attribute.

class Example {
  Example(this.line, this.lineNo);
  String line;
  int lineNo;
}

class GroupStats {
  GroupStats(this.key, this.description);

  int count = 0;
  Example? firstExample;
  Example? lastExample;
  String description;
  Risk risk = Risk.none;

  String key;

  void addExample(Rule rule, Selector selector, String example, int lineNo) {
    if (firstExample == null) {
      firstExample = Example(example, lineNo);
    } else {
      lastExample = Example(example, lineNo);
    }
    if (selector.risk.index > risk.index) {
      risk = selector.risk;
    }
    count++;
  }
}

mixin GroupedSourceAnalyserMixin on GroupedSourceAnalyser {
  Map<String, GroupStats> logStatsMap = <String, GroupStats>{};

  @override
  int matchCount = 0;

  @override
  void processMatch(
      LogSource source, Rule rule, Selector selector, String line, int lineNo) {
    matchCount++;

    /// the selector matched the line.
    final key = getGroup(line, selector);

    var logStats = logStatsMap[key];
    if (logStats == null) {
      logStats = GroupStats(key, selector.description);
      logStatsMap[key] = logStats;
    }

    /// log an example line.
    logStats.addExample(rule, selector, line, lineNo);
  }

  @override
  StringBuffer prepareReport(LogSource source, StringBuffer sb) {
    printStats(logStatsMap, source, sb);
    return sb;
  }

  void printStats(
      Map<String, GroupStats> logStatsMap, LogSource source, StringBuffer sb) {
    final sorted = <GroupStats>[];
    logStatsMap.values.forEach(sorted.add);

    sorted.sort((a, b) {
      if (a.risk == b.risk) {
        return b.count - a.count;
      } else {
        return b.risk.index - a.risk.index;
      }
    });

    Risk? current;
    var ctr = 0;
    for (final logStats in sorted) {
      ctr++;
      if (ctr > source.top) {
        break;
      }

      if (logStats.risk != current) {
        if (current != null) {
          sb.writeln();
        }
        writeRiskHeader(logStats.risk, sb);
        current = logStats.risk;
      }

      sb.write('''
${logStats.description} (occurred: ${logStats.count})
''');

      if (logStats.lastExample != null) {
        final last = 'LAST  ${logStats.lastExample!.lineNo} '
            '${logStats.lastExample!.line}';
        final first = 'FIRST line: ${logStats.firstExample!.lineNo} '
            '${logStats.firstExample!.line}';

        sb.write('''
  $first
  $last 
  ''');
      } else {
        sb.writeln('''
  line: ${logStats.firstExample?.lineNo} ${logStats.firstExample!.line}''');
      }
    }

    if (logStatsMap.isEmpty) {
      sb.write(green('No problems found'));
    }
  }

  void writeRiskHeader(Risk risk, StringBuffer sb) {
    sb
      ..writeln('*' * 80)
      ..writeln('* ${' ' * 20} ${EnumHelper().getName(risk)}')
      ..writeln('*' * 80);
  }
}
