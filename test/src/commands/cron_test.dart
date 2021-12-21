import 'package:cron/cron.dart';
import 'package:dcli/dcli.dart';
import 'package:test/test.dart';

void main() {
  test('cron ...', () async {
    const scheduleArg = '0 30 22 * * *';

    final Schedule schedule;
    try {
      schedule = Schedule.parse(scheduleArg);
      // ignore: avoid_catches_without_on_clauses
    } catch (e) {
      print(red('Failed to parse schedule: "$scheduleArg" ${e.toString()}'));
      return 1;
    }
    expect(
        schedule.shouldRunAt(DateTime.now().copyWith(
          hour: 22,
          minute: 30,
          second: 0,
          millisecond: 0,
          microsecond: 0,
        )),
        isTrue);
  });
}

extension MyDateUtils on DateTime {
  DateTime copyWith({
    int? year,
    int? month,
    int? day,
    int? hour,
    int? minute,
    int? second,
    int? millisecond,
    int? microsecond,
  }) =>
      DateTime(
        year ?? this.year,
        month ?? this.month,
        day ?? this.day,
        hour ?? this.hour,
        minute ?? this.minute,
        second ?? this.second,
        millisecond ?? this.millisecond,
        microsecond ?? this.microsecond,
      );
}
