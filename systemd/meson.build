systemd_dep = dependency('systemd')
systemd_system_unit_dir = systemd_dep.get_variable('systemdsystemunitdir')

install_data(
	'isolate.slice',
	install_dir: systemd_system_unit_dir,
)

configure_file(
	input: 'isolate.service.in',
	output: 'isolate.service',
	configuration: {
		'SBINDIR': sbindir,
	},
	install: true,
	install_dir: systemd_system_unit_dir,
)
