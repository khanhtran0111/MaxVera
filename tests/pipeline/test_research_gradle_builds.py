"""Gradle recipes must compile again when CodeQL repeats a successful build."""

import subprocess
import sys

import pytest

from src.data.build_projects import build_command_and_env


@pytest.mark.parametrize("wrapper", [False, True], ids=["installed", "wrapper"])
def test_gradle_recipe_recompiles_for_tracing_without_running_tests(tmp_path, wrapper):
    source = tmp_path / "source"
    source.mkdir()
    executable = source / "gradlew" if wrapper else tmp_path / "tools/gradle/bin/gradle"
    executable.parent.mkdir(parents=True, exist_ok=True)
    # A small local tool fixture reproduces Gradle's clean/build and UP-TO-DATE
    # behavior without requiring a Gradle distribution or downloading plugins.
    executable.write_text(
        f"#!{sys.executable}\n"
        "import pathlib, shutil, sys\n"
        "args = sys.argv[1:]\n"
        "output = pathlib.Path('build')\n"
        "if 'clean' in args:\n"
        "    shutil.rmtree(output, ignore_errors=True)\n"
        "if 'build' in args:\n"
        "    if '-x' not in args or args[args.index('-x') + 1] != 'test':\n"
        "        pathlib.Path('tests-ran').touch()\n"
        "    if not (output / 'Main.class').exists():\n"
        "        output.mkdir(exist_ok=True)\n"
        "        (output / 'Main.class').write_bytes(b'compiled')\n"
        "        with pathlib.Path('compilations.log').open('a') as log:\n"
        "            log.write('compiled\\n')\n"
    )
    executable.chmod(0o700)
    toolchains = {
        "install_root": "tools",
        "jdk": {"17": {"env_home": "MAXVERA_JAVA_17_HOME"}},
        "gradle": {"8.9": {"directory": "gradle"}},
    }
    attempt = {"jdk": "17", **({"gradlew": True} if wrapper else {"gradle": "8.9"})}
    command, environment = build_command_and_env(
        tmp_path, source, attempt, toolchains, {"MAXVERA_JAVA_17_HOME": str(tmp_path / "jdk")}
    )

    # The pipeline first probes the build and then repeats it under CodeQL.
    for _ in range(2):
        subprocess.run(command, cwd=source, env=environment, check=True, timeout=10)

    assert (source / "build/Main.class").is_file(), "the recipe must compile Java"
    assert (source / "compilations.log").read_text().splitlines() == ["compiled", "compiled"]
    assert not (source / "tests-ran").exists()
