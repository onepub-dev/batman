/* Copyright (C) S. Brett Sutton - All Rights Reserved
 * Unauthorized copying of this file, via any medium is strictly prohibited
 * Proprietary and confidential
 * Written by Brett Sutton <bsutton@onepub.dev>, Jan 2022
 */


import '../../rules/matched.dart';
import '../../rules/rule.dart';
import '../../rules/selectors/selector.dart';

import '../log_sources/log_source.dart';

/// an interface for [LogSource]s designed
/// to allow them to collate data across the logs
abstract class SourceAnalyser {
  /// Returns the no. of lines that matched.
  int get matchCount;

  /// Gives the analyzer a chance to modify the line before it
  /// is passed for matching.
  String preProcessLine(LogSource logSource, String line, int lineCounter);

  /// Allows the Analyser to check if the line matches its rules.
  ///
  /// Called each time a line is read from the source.
  /// A line may match on multiple rules/selectors.
  /// Return a [Match] for each time the line matches.
  List<Matched> testForMatches(LogSource source, String line, int lineNo);

  /// Called for each line that matched.
  ///
  void processMatch(
      LogSource source, Rule rule, Selector selector, String line, int lineNo);

  StringBuffer prepareReport(LogSource logSource, StringBuffer sb);
}

class NoopAnalyser implements SourceAnalyser {
  @override
  String preProcessLine(LogSource logSource, String line, int lineCounter) =>
      line;

  @override
  List<Matched> testForMatches(LogSource source, String line, int lineNo) =>
      <Matched>[];

  /// process [testForMatches] calls.
  @override
  void processMatch(LogSource source, Rule rule, Selector selector, String line,
      int lineNo) {}

  @override
  int get matchCount => 0;

  @override
  StringBuffer prepareReport(LogSource logSource, StringBuffer sb) => sb;
}
