export 'docker_log_source.dart';
export 'file_log_source.dart';
export 'njcontact_log_source.dart';

import 'package:batman/src/selectors/selectors.dart';
import 'package:settings_yaml/settings_yaml.dart';

import '../log.dart';
import '../rules.dart';
import '../selectors/selector.dart';

import 'log_source.dart';
import 'log_sources.dart';

class LogAudits {
  List<Selector> globalSelectors = <Selector>[];
  List<LogSource> sources = <LogSource>[];

  LogAudits.fromSettings(SettingsYaml settings) {
    var location = 'log_audits.global_selectors';
    final glist = settings.selectAsList(location);
    if (glist != null) {
      for (var i = 0; i < glist.length; i++) {
        globalSelectors
            .add(Selectors().fromMap(settings, '$location.selector[$i]'));
      }
    } else {
      log('Info: no global_selectors found in rules.yaml');
    }

    location = 'log_audits.log_sources';
    final slist = settings.selectAsList(location);

    if (slist != null) {
      for (var i = 0; i < slist.length; i++) {
        sources.add(LogSources.fromMap(settings, '$location.log_source[$i]'));
      }
    } else {
      RuleLogger().info(() => 'no log_sources found in rules.yaml');
    }
  }
}
