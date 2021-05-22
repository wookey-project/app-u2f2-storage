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
#if STORAGE_DEBUG
# define log_printf(...) printf(__VA_ARGS__)
#else
# define log_printf(...)
#endif



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
    if ((errcode = fidostorage_get_appid_slot(&appid[0], NULL, &slot, &hmac[0], NULL, false)) != MBED_ERROR_NONE) {
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
     * get back cryptographic inputs (encryption+integrity key, anti-rollback)
     ***********************************************/
    printf("[storage] get back storage assets from FIDO\n");
    int msqr;
    struct msgbuf msgbuf = { 0 };
    size_t msgsz = 0;

    uint8_t aes_key[32];

    msgbuf.mtype = MAGIC_STORAGE_GET_ASSETS;
    msqr = msgsnd(fido_msq, &msgbuf, 0, 0);
    if (msqr < 0) {
        printf("[storage] failed to get back storage assets from Fido, errno=%d\n", errno);
        goto error;
    }

    /* get back AES master key */
    msgsz = 32;
    if ((msqr = msgrcv(fido_msq, &msgbuf, msgsz, MAGIC_STORAGE_SET_ASSETS_MASTERKEY, 0)) < 0) {
        printf("[storage] failed while trying to receive AES encryption key, errno=%d\n", errno);
        goto error;
    }
    if (msqr < 32) {
        printf("[storage] received AES encryption key too small: %d bytes\n", msqr);
        goto error;
    }
    memcpy(&aes_key[0], &msgbuf.mtext.u8[0], 32);

    /* get back sd anti-rollback counter from the token */
    msgsz = 8;
    if ((msqr = msgrcv(fido_msq, &msgbuf, msgsz, MAGIC_STORAGE_SET_ASSETS_ROLLBK, 0)) < 0) {
        printf("[storage] failed while trying to receive anti-rollback counter, errno=%d\n", errno);
        goto error;
    }
    if (msqr < 8) {
        printf("[storage] received rollback counter too small: %d bytes\n", msqr);
        goto error;
    }

    /* XXX: FIX using hardcoded AES key while not yet communicating with FIDO app */

    printf("Fido informed.\n");

    /*******************************************
     * Main read/write loop
     *   SDIO is waiting for READ/WRITE command
     *   from IPC interface
     *******************************************/
    /*
       512 bytes is the mandatory blocksize for SD card >= HC
       it is also mandatorily support by the other cards so it can be hardcoded
    */

    sd_set_block_len(512);


    /* Inject our keys for encryption and integrity */
    fidostorage_configure(buf, STORAGE_BUF_SIZE, &aes_key[0]);
  
    mbed_error_t errcode;

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

    appid[31] = 0xa4;
    printf("[fiostorage] starting appid measurement\n");
    errcode = fidostorage_get_appid_slot(&appid[0], NULL, &slot, &hmac[0], NULL, false);
    if (errcode != MBED_ERROR_NONE) {
        printf("appid 0xcc..a4 not found!\n");
    }

    errcode = fidostorage_get_appid_metadata(&appid[0], NULL, slot, &hmac[0], mt);
    printf("appid 0xcc..a4 name is %s\n", mt->name);

    appid[31] = 0xc5;
    errcode = fidostorage_get_appid_slot(&appid[0], NULL, &slot, &hmac[0], NULL, false);
    if (errcode != MBED_ERROR_NONE) {
        printf("appid 0xcc..c5 not found!\n");
    }

    errcode = fidostorage_get_appid_metadata(&appid[0], NULL, slot, &hmac[0], mt);


    appid[30] = 0x00;
    appid[31] = 0x11;

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
    appid[30] = 0x00;
    appid[31] = 0x11;
    printf("==> get appid (full header + slot access)\n");
    fidostorage_get_appid_slot(&appid[0], &kh_hash[0], &slot, &hmac[0], NULL, false);
    fidostorage_get_appid_metadata(&appid[0], &kh_hash[0], slot, &hmac[0], mt);
    printf("==> Purge Appid\n");
    fidostorage_set_appid_metada(&slot, NULL);

    //
    appid[30] = 0xcc;
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
    printf("==> Upgrade Appid\n");
    fidostorage_set_appid_metada(&slot, metadata);

#endif


    printf("SDIO main loop starting\n");
    /*
     * Main waiting loop. The task main thread is awoken by any external
     * event such as ISR or IPC.
     */

    msgsz = 64;

    /* Now that the storage is configured, we globally check the integrity of our header */
    /* NOTE: calling fidostorage_get_appid_slot with NULL as appid will ask for a header
     * integrity check!
     */
    uint8_t sd_replay_ctr[8] = { 0 };
    errcode = fidostorage_get_appid_slot(NULL, NULL, NULL, NULL, sd_replay_ctr, true);
    if (errcode != MBED_ERROR_NONE) {
        printf("SD integrity is NOT OK!\n");
        goto error;
    }

    /* We can check our anti-rollback counter */
    

    /* XXX TODO: increment anti-rollback counter on the two sides */


    do {
        msqr = msgrcv(fido_msq, &msgbuf, msgsz, MAGIC_STORAGE_GET_METADATA, IPC_NOWAIT);
        if (msqr >= 0) {
            log_printf("[storage] received MAGIC_STORAGE_GET_METADATA from Fido\n");
            /* appid is given by FIDO */
            uint8_t *appid = &msgbuf.mtext.u8[0];
            mbed_error_t errcode;
            errcode = prepare_and_send_appid_metadata(fido_msq, appid);
            /* get back content associated to appid */
            goto endloop;
        }

        msqr = msgrcv(fido_msq, &msgbuf, msgsz, MAGIC_STORAGE_SET_METADATA, IPC_NOWAIT);
        if (msqr >= 0) {
            log_printf("[storage] received MAGIC_STORAGE_SET_METADATA from Fido\n");
            goto endloop;
        }

        msqr = msgrcv(fido_msq, &msgbuf, msgsz, MAGIC_STORAGE_INC_CTR, IPC_NOWAIT);
        if (msqr >= 0) {
            log_printf("[storage] received MAGIC_STORAGE_INC_CTR from Fido\n");
            if (msqr < 32) {
                printf("[storage] appid given too short: %d bytes\n", msqr);
            }
            uint8_t *appid = &msgbuf.mtext.u8[0];
            if (fidostorage_get_appid_slot(appid, &kh_hash[0], &slot, &hmac[0], NULL, false)) {
                printf("[storage] appid given by fido not found\n");
                goto endloop;
            }
            if (fidostorage_get_appid_metadata(&appid[0], &kh_hash[0], slot, &hmac[0], mt)) {
                printf("[storage] failed to get back appid metadata\n");
            }
            /* increment counter. What FIDO says for UINT32_MAX ? */
            mt->ctr++;
            if (fidostorage_set_appid_metada(&slot, metadata)) {
                printf("[storage] failed to set back appid CTR\n");
            }
            /* XXX: acknowledge FIDO */
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
