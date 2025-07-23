#include <stdio.h>
#include <pcap.h>

#include "capture.h"

/* To build this program, use the following command:
 * gcc -o tcp-analyzer main.c -lpcap
*/

int main(void)
{
    packet_capture();
    return 0;

}