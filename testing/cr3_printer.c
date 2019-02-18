#include<sys/param.h>
#include<sys/module.h>
#include<sys/kernel.h>
#include<sys/systm.h>
#include<vm/vm.h>
#include<vm/pmap.h>

static void print_symbols() {
	uprintf("kernel_pmap: %p\n", kernel_pmap);
	uprintf("pm_cr3: %lu\n", kernel_pmapi->pm_cr3);
}



/* The function called at load/unload. */
static int load(struct module *module, int cmd, void *arg) {
	int error = 0;
	
	switch (cmd) {
	case MOD_LOAD:
		uprintf("Hello, world!\n");
		break;
	case MOD_UNLOAD:
		uprintf("Good-bye, cruel world!\n");
		break;
	default:
		error = EOPNOTSUPP;
		break;
	}
	
	return(error);
}

/* The second argument of DECLARE_MODULE. */
static moduledata_t hello_mod = {
	"hello", /* module name */
	load,    /* event handler */
	NULL     /* extra data */
};

DECLARE_MODULE(hello, hello_mod, SI_SUB_DRIVERS, SI_ORDER_MIDDLE);
