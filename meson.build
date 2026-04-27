project(
	'isolate',
	['c'],
	default_options: [
		'c_std=gnu99',
		'warning_level=3',
		'buildtype=debugoptimized',
	],
	license: 'GPL2-or-later',
	version: '2.1',
	meson_version: '>= 1.1',
)

prefix = get_option('prefix')
sbindir = prefix / get_option('sbindir')
sysconfdir = prefix / get_option('sysconfdir')
box_root = prefix / get_option('sharedstatedir') / get_option('box_root')

conf_file = sysconfdir / 'isolate.conf'
configure_file(
	input: 'default.cf.in',
	output: 'isolate.conf',
	configuration: {
		'BOXDIR': box_root,
	},
	install: true,
	install_dir: sysconfdir,
)

install_emptydir(
	box_root,
	install_mode: ['rwxr-xr-x', 0, 0],
)

fs = import('fs')

if fs.exists('build-date')
	build_date = fs.read('build-date')
else
	build_date = run_command('date', '+%Y-%m-%d', capture: true, check: true).stdout().strip()
endif

build_commit = ''

if fs.exists('build-commit')
	build_commit = fs.read('build-commit')
else
	git_cmd = run_command('git', 'describe', '--always', '--tags', capture: true, check: false, env: {
		'GIT_WORK_TREE': meson.project_source_root(),
	})

	if git_cmd.returncode() == 0
		build_commit = git_cmd.stdout().strip()
	endif
endif

if build_commit == ''
	build_commit = '<unknown>'
endif

# compilation setup

cc = meson.get_compiler('c')

add_project_arguments(
	cc.get_supported_arguments([
		'-Wno-parentheses',
		'-Wno-unused-result',
		'-Wno-missing-field-initializers',
		'-Wstrict-prototypes',
		'-Wmissing-prototypes',
		'-D_FORTIFY_SOURCE=3',
		'-D_GNU_SOURCE',
		'-fstack-protector-strong',
		'-fstack-clash-protection',
	]),
	language: 'c',
)

common_c_args = [
	'-DISOLATE_VERSION="@0@"'.format(meson.project_version()),
	'-DISOLATE_YEAR="2025"',
	'-DBUILD_DATE="@0@"'.format(build_date),
	'-DBUILD_COMMIT="@0@"'.format(build_commit),
	'-DCONFIG_FILE="@0@"'.format(conf_file),
]

common_link_args = [
	'-Wl,-z,nodlopen',
	'-Wl,-z,noexecstack',
	'-Wl,-z,relro',
	'-Wl,-z,now',
]

# isolate

libcap_dep = dependency('libcap')

executable(
	'isolate',
	sources: [
		'isolate.c',
		'util.c',
		'rules.c',
		'cg.c',
		'config.c',
	],
	dependencies: [
		libcap_dep,
	],
	c_args: common_c_args,
	link_args: common_link_args,
	install: true,
	install_mode: ['rwsr-xr-x', 0, 0],
)

# isolate-check-environment

install_data(
	'isolate-check-environment',
	install_dir: get_option('bindir'),
)

# isolate-cg-keeper

libsystemd_dep = dependency('libsystemd')

isolate_cg_keeper = executable(
	'isolate-cg-keeper',
	sources: [
		'isolate-cg-keeper.c',
		'config.c',
		'util.c',
	],
	dependencies: [
		libsystemd_dep,
	],
	c_args: common_c_args,
	link_args: common_link_args,
	install: true,
	install_dir: sbindir,
)

# docs

a2x = find_program('a2x', required: false)
if a2x.found()
	foreach name, section : {
		'isolate': 1,
		'isolate-check-environment': 8,
		'isolate-cg-keeper': 8,
	}
		input = '@0@.@1@.txt'.format(name, section)

		man_page = custom_target(
			'docs-man-@0@'.format(name),
			output: '@0@.@1@'.format(name, section),
			input: input,
			command: [a2x, '-f', 'manpage', '-D', meson.current_build_dir(), '@INPUT@'],
			install: true,
			install_dir: get_option('mandir') / 'man@0@'.format(section),
			install_tag: 'man',
		)

		html_page = custom_target(
			'docs-html-@0@'.format(name),
			output: '@0@.@1@.html'.format(name, section),
			input: input,
			command: [a2x, '-f', 'xhtml', '-D', meson.current_build_dir(), '@INPUT@'],
			install: true,
			install_dir: get_option('sharedstatedir') / 'doc' / 'isolate',
			install_tag: 'man',

			# The dependency on `man_page` is there to serialize both calls of asciidoc,
			# which does not name temporary files safely.
			depends: man_page,
		)
	endforeach
endif

# ---

subdir('systemd')
