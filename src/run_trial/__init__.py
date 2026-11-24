"""One-command runner per trial (spec 06_evaluate section 4 B, RT-01..RT-11; decision 072 item 3).

``python -m run_trial --trial <t> | --development [--repo R]`` rebuilds a development trial from its database to
its evaluation by calling every stage as its own subprocess (gate -> stitch -> label -> score -> evaluate). Each stage
keeps its own refusals; the runner adds only the allowlist check (RT-01) and the upstream presence check (RT-02),
measures the wall time of every step (RT-07) and writes ``out/run_trial/<t>/run_log.json``.

``python -m run_trial.dryrun`` (DR-01..DR-07) runs the whole development chain in a scratch copy of the repository
and compares the outputs with the committed ``out/``.

``python -m run_trial.ablation`` (spec 06 AB-01..AB-11) runs the same chain in a scratch copy with stitch's
``cmdline_target`` method disabled and writes the side-by-side tables to ``out/ablation/no_cmdline/``.

Module map: ``params`` (names, file lists), ``steps`` (argv building, pure), ``checks`` (RT-01/RT-02/RT-08 and
AB-06 checks), ``execute`` (subprocess, timing, post-check), ``runlog`` (log texts and the only writer), ``__main__``
(CLI), ``dryrun`` / ``dryrun_compare`` (DR-01..DR-07), ``ablation`` / ``ablation_report`` (AB-02..AB-11).
"""
