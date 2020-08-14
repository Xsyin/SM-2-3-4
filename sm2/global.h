//
// Created by lxb on 3/15/16.
//

#ifndef TESTNDK_GLOBAL_H
#define TESTNDK_GLOBAL_H

#endif //TESTNDK_GLOBAL_H
#pragma once
#define MAX_KG (4*1024*1024)
#define BUFFER_SIZE (1024*50)
#define TCP_BUF_LEN BUFFER_SIZE
#define MAX_NET_LEN (TCP_BUF_LEN - 512)
#define RND_LIST_LEN (32*1024*1024)
#define MAX_SEESION (1024*1024)
#define MAX_SEESIONCOUNT (3600)
#define MAX_SIM_QIUNI (128)
#define MAX_EVENT 32








#define IS_TOKEN                     0x00000001  /* token obj */
#define IS_LOCAL      0x00000002  /* generated locally*/
#define CAN_ENCRYPT          0x00000004  /*  */
#define CAN_DECRYPT    0x00000008  /* */
#define CAN_VERIFY    0x00000010  /*  */
#define CAN_SIGN    0x00000020  /* */

#define KEY_CLASS_PUBLIC_KEY 0X00000002
#define KEY_CLASS_PRIVATE_KEY 0X00000003
#define KEY_CLASS_SECRET_KEY 0X00000004

#define KEY_TYPE_SM2 0X80000001
#define KEY_TYPE_SM4 0X80000002

extern float g_sessioncount;
extern float g_netcount;
extern float g_count;
extern float g_scount;
extern float g_vcount;
extern float g_ecount;
extern float g_dcount;
extern float g_speed;
extern float g_sspeed;
extern float g_vspeed;
extern float g_espeed;
extern float g_dspeed;

__inline__ void swap(char* out, char * in, int num )
{
    for(int i=0;i<num;i++)out[i] = in[num - i - 1];
}
