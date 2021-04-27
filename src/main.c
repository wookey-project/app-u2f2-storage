/**
 * @file main.c
 *
 * \brief Main of dummy
 *
 */

#include "autoconf.h"
#include "libc/syscall.h"
#include "libc/stdio.h"
#include "libc/nostd.h"
#include "libc/string.h"
#include "libc/sys/msg.h"
#include "libc/errno.h"
#include "libsdio.h"
#include "libsd.h"
#include "libcryp.h"
#include "libu2f2.h"
#include "libfidostorage.h"

#include "generated/led1.h"

/*
 * We use the local -fno-stack-protector flag for main because
 * the stack protection has not been initialized yet.
 *
 * We use _main and not main to permit the usage of exactly *one* arg
 * without compiler complain. argc/argv is not a goot idea in term
 * of size and calculation in a microcontroler
 */
#define STORAGE_DEBUG 0
#define STORAGE_BUF_SIZE 4096

/* NOTE: alignment due to DMA */
__attribute__ ((aligned(4)))
     uint8_t buf[STORAGE_BUF_SIZE] = { 0 };

extern volatile uint8_t SD_ejection_occured;

#if CONFIG_USE_SD_LOCK /* We only use SD lock if it has been asked by the user! */
static uint8_t sdio_once = 0;
#endif

static inline void led_on(void)
{
    /* Toggle led ON */
    sys_cfg(CFG_GPIO_SET,
            (uint8_t) ((led1_dev_infos.gpios[LED1].port << 4) +
                       led1_dev_infos.gpios[LED1].pin), 1);
}


static inline void led_off(void)
{
    /* Toggle led OFF */
    sys_cfg(CFG_GPIO_SET,
            (uint8_t) ((led1_dev_infos.gpios[LED1].port << 4) +
                       led1_dev_infos.gpios[LED1].pin), 0);
}


void SDIO_asks_reset(uint8_t fido_msq)
{
    // TODO
    fido_msq = fido_msq;
}

int fido_msq = 0;
uint8_t hmac[32] = { 0x0 };


mbed_error_t prepare_and_send_appid_metadata(int msq, uint8_t  *appid)
{
    uint32_t slot;
    mbed_error_t errcode = MBED_ERROR_NONE;
    if ((errcode = fidostorage_get_appid_slot(&appid[0], NULL, &slot, &hmac[0])) != MBED_ERROR_NONE) {
        errcode = send_appid_metadata(msq, appid, NULL, NULL);
        goto err;
    }
    fidostorage_appid_slot_t *mt = (fidostorage_appid_slot_t *)&buf[0];
    if ((errcode = fidostorage_get_appid_metadata(&appid[0], NULL, slot, &hmac[0], mt)) != MBED_ERROR_NONE) {
        errcode = send_appid_metadata(msq, appid, NULL, NULL);
        goto err;
    }
    errcode = send_appid_metadata(msq, appid, mt, &mt->icon.icon_data[0]);
err:
    return errcode;
}



int _main(uint32_t task_id)
{
    e_syscall_ret ret;
    char   *wellcome_msg = "hello, I'm storage";
    int     led_desc;

    printf("%s, my id is %x\n", wellcome_msg, task_id);

    fido_msq = msgget("fido", IPC_CREAT | IPC_EXCL);
    if (fido_msq == -1) {
        printf("error while requesting SysV message queue. Errno=%x\n", errno);
        goto error;
    }

    /* Early init phase of drivers/libs */
    if (sd_early_init()) {
        printf("SDIO KO !!!!! \n");
    }

    // PTH test cryp
    fidostorage_declare();

#if CONFIG_WOOKEY
    /*********************************************
     * Declaring SDIO read/write access LED
     ********************************************/

    printf("Declaring SDIO LED device\n");
    device_t dev;

    memset(&dev, 0, sizeof(device_t));
    strncpy(dev.name, "sdio_led", sizeof("sdio_led"));
    dev.gpio_num = 1;
    dev.gpios[0].mask =
        GPIO_MASK_SET_MODE | GPIO_MASK_SET_PUPD | GPIO_MASK_SET_SPEED;
    dev.gpios[0].kref.port = led1_dev_infos.gpios[LED1].port;
    dev.gpios[0].kref.pin = led1_dev_infos.gpios[LED1].pin;
    dev.gpios[0].pupd = GPIO_NOPULL;
    dev.gpios[0].mode = GPIO_PIN_OUTPUT_MODE;
    dev.gpios[0].speed = GPIO_PIN_HIGH_SPEED;

    ret = sys_init(INIT_DEVACCESS, &dev, &led_desc);
    if (ret != SYS_E_DONE) {
        printf("Error while declaring LED GPIO device: %d\n", ret);
        goto error;
    }
#endif

    /*******************************************
     * End of init
     *******************************************/

    printf("set init as done\n");
    ret = sys_init(INIT_DONE);
    printf("sys_init returns %s !\n", strerror(ret));

#if CONFIG_WOOKEY
    led_on();
    sys_sleep(1000, SLEEP_MODE_INTERRUPTIBLE);
    led_off();
#endif

    /*******************************************
     * Let's syncrhonize with other tasks
     *******************************************/

    /* Init phase of drivers/libs */
#if 0
    if (SD_ejection_occured) {
        SDIO_asks_reset(fido_msq);
    }
#endif
    sd_init();

    /************************************************
     * Sending crypto end_of_service_init
     ***********************************************/

    /*******************************************
     * Sharing DMA SHM address and size with crypto
     *******************************************/

#if 0
    ipc_sync_cmd_data.magic = MAGIC_DMA_SHM_INFO_CMD;
    ipc_sync_cmd_data.state = SYNC_READY;
    ipc_sync_cmd_data.data_size = 2;
    ipc_sync_cmd_data.data.u32[0] = (uint32_t) sdio_buf;
    ipc_sync_cmd_data.data.u32[1] = SDIO_BUF_SIZE;

    printf("informing crypto about DMA SHM...\n");
    ret =
        sys_ipc(IPC_SEND_SYNC, id_crypto, sizeof(struct sync_command_data),
                (char *) &ipc_sync_cmd_data);
    if (ret != SYS_E_DONE) {
        printf("sys_ipc(IPC_SEND_SYNC, id_crypto) failed! Exiting...\n");
        goto error;
    }

    ret = sys_ipc(IPC_RECV_SYNC, &id, &size, (char *) &ipc_sync_cmd);
    if (ret != SYS_E_DONE) {
        printf("sys_ipc(IPC_RECV_SYNC) failed! Exiting...\n");
        goto error;
    }
    if ((ipc_sync_cmd.magic == MAGIC_DMA_SHM_INFO_RESP)
        && (ipc_sync_cmd.state == SYNC_ACKNOWLEDGE)) {
        printf("crypto has acknowledge DMA SHM, continuing\n");
    } else {
        printf("Error ! IPC desynchro !\n");
        goto error;
    }
#endif
    /* XXX: FIX using hardcoded AES key while not yet communicating with FIDO app */

    printf("Fido informed.\n");

    /*******************************************
     * Main read/write loop
     *   SDIO is waiting for READ/WRITE command
     *   from IPC interface
     *******************************************/
    /*
       512 nytes is the mandatory blocksize for SD card >= HC
       it is also mandatorily support by the other cards so it can be hardcoded
    */

    sd_set_block_len(512);

    uint8_t aes_key[32] = {
        0xaa,
        0xaa,
        0xaa,
        0xaa,
        0xaa,
        0xaa,
        0xaa,
        0xaa,
        0xaa,
        0xaa,
        0xaa,
        0xaa,
        0xaa,
        0xaa,
        0xaa,
        0xaa,
        0xaa,
        0xaa,
        0xaa,
        0xaa,
        0xaa,
        0xaa,
        0xaa,
        0xaa,
        0xaa,
        0xaa,
        0xaa,
        0xaa,
        0xaa,
        0xaa,
        0xaa,
        0xaa,
    };


    fidostorage_configure(buf, STORAGE_BUF_SIZE, &aes_key[0]);

#if 1
    //sys_sleep(7000, SLEEP_MODE_INTERRUPTIBLE);
    uint32_t slot;
    uint8_t appid[32] = {
    0xcc,
    0xcc,
    0xcc,
    0xcc,
    0xcc,
    0xcc,
    0xcc,
    0xcc,
    0xcc,
    0xcc,
    0xcc,
    0xcc,
    0xcc,
    0xcc,
    0xcc,
    0xcc,
    0xcc,
    0xcc,
    0xcc,
    0xcc,
    0xcc,
    0xcc,
    0xcc,
    0xcc,
    0xcc,
    0xcc,
    0xcc,
    0xcc,
    0xcc,
    0xcc,
    0xcc,
    0xc5
     };
    /* we reuse the global buffer for metadata to reduce memory consumption */
    fidostorage_appid_slot_t *mt = (fidostorage_appid_slot_t *)&buf[0];

    printf("[fiostorage] starting appid measurement\n");
    fidostorage_get_appid_slot(&appid[0], NULL, &slot, &hmac[0]);
    fidostorage_get_appid_metadata(&appid[0], NULL, slot, &hmac[0], mt);

    uint8_t tmp[SLOT_MT_SIZE] = { 0 };
    fidostorage_appid_slot_t *metadata = (fidostorage_appid_slot_t*)tmp;
    memcpy(metadata->appid, appid, sizeof(appid));
    const char toto[] = "Alcatraz";
    memcpy(metadata->name, toto, sizeof(toto));
    metadata->flags = 0x1337;
    metadata->ctr = 0xaabb;
    metadata->icon_len = 3;
    metadata->icon_type = 1;
    metadata->icon.rgb_color[0] = 0xaa;
    metadata->icon.rgb_color[1] = 0xbb;
    metadata->icon.rgb_color[2] = 0xcc;

    fidostorage_set_appid_metada(&slot, metadata);

    uint8_t kh_hash[32] = {
    0xab,
    0xab,
    0xab,
    0xab,
    0xab,
    0xab,
    0xab,
    0xab,
    0xab,
    0xab,
    0xab,
    0xab,
    0xab,
    0xab,
    0xab,
    0xab,
    0xab,
    0xab,
    0xab,
    0xab,
    0xab,
    0xab,
    0xab,
    0xab,
    0xab,
    0xab,
    0xab,
    0xab,
    0xab,
    0xab,
    0xab,
    0xab
     };
    appid[31] = 0xcc;
    fidostorage_get_appid_slot(&appid[0], &kh_hash[0], &slot, &hmac[0]);
    fidostorage_get_appid_metadata(&appid[0], &kh_hash[0], slot, &hmac[0], mt);
    fidostorage_set_appid_metada(&slot, NULL);

    //
    appid[31] = 0xc5;
    memcpy(metadata->appid, appid, sizeof(appid));
    memcpy(metadata->kh, kh_hash, sizeof(kh_hash));
    const char toto2[] = "San Francisco";
    memcpy(metadata->name, toto2, sizeof(toto2));
    metadata->flags = 0xff;
    metadata->ctr = 0xeeff;
    metadata->icon_len = 3;
    metadata->icon_type = 1;
    metadata->icon.rgb_color[0] = 0xff;
    metadata->icon.rgb_color[1] = 0xff;
    metadata->icon.rgb_color[2] = 0xff;

    slot = 0;
    fidostorage_set_appid_metada(&slot, metadata);

#endif


    printf("SDIO main loop starting\n");
    /*
     * Main waiting loopt. The task main thread is awoken by any external
     * event such as ISR or IPC.
     */

    int msqr;
    struct msgbuf msgbuf = { 0 };
    size_t msgsz = 64;

    do {
        msqr = msgrcv(fido_msq, &msgbuf, msgsz, MAGIC_STORAGE_GET_METADATA, IPC_NOWAIT);
        if (msqr >= 0) {
            printf("[storage] received MAGIC_STORAGE_GET_METADATA from Fido\n");
            /* appid is given by FIDO */
            uint8_t *appid = &msgbuf.mtext.u8[0];
            mbed_error_t errcode;
            errcode = prepare_and_send_appid_metadata(fido_msq, appid);
            /* get back content associated to appid */
            goto endloop;
        }
        msqr = msgrcv(fido_msq, &msgbuf, msgsz, MAGIC_STORAGE_SET_METADATA, IPC_NOWAIT);
        if (msqr >= 0) {
            printf("[storage] received MAGIC_STORAGE_SET_METADATA from Fido\n");
            goto endloop;
        }
        /* no message received ? As FIDO is a slave task, sleep for a moment... */
        sys_sleep(500, SLEEP_MODE_INTERRUPTIBLE);
endloop:
        continue;

    } while (1);

 error:
    printf("Error! critical SDIO error, leaving!\n");
    return 1;
}
