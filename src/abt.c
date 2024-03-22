#include "../include/simulator.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
/* ******************************************************************
 ALTERNATING BIT AND GO-BACK-N NETWORK EMULATOR: VERSION 1.1  J.F.Kurose

   This code should be used for PA2, unidirectional data transfer 
   protocols (from A to B). Network properties:
   - one way network delay averages five time units (longer if there
     are other messages in the channel for GBN), but can be larger
   - packets can be corrupted (either the header or the data portion)
     or lost, according to user-defined probabilities
   - packets will be delivered in the order in which they were sent
     (although some can be lost).
**********************************************************************/

/********* STUDENTS WRITE THE NEXT SIX ROUTINES *********/

// Global variables for A
int A_seqnum; 
int A_expected_ack; // to keep track of the expected ack from b
int A_waiting_for_ack; // flag to keep trck of acks
struct pkt A_last_packet; // last packet sent
struct msg A_buffer; // buffer for messages
int A_buffered; // buffer flag

// Global variables for B
int B_expected_seqnum;
int B_last_acknowledged_seqnum;
struct pkt B_last_ackpacket; // store the last ACK packet sent by B


// estimated buffer size value
#define MAX_BUFFER_SIZE 1000
// estimated timeout value
#define TIMEOUT 10 // average of 5 time units to arrive at the other side 

struct message_queue {
    struct msg buffer[MAX_BUFFER_SIZE];
    int front, end, size;
} A_message_queue;

// To put messages in a queue
void enqueue(struct msg message) {
  // if queue not full add to the end and increment
    if (A_message_queue.size < MAX_BUFFER_SIZE) {
        A_message_queue.end = (A_message_queue.end + 1) % MAX_BUFFER_SIZE;
        A_message_queue.buffer[A_message_queue.end] = message;
        A_message_queue.size++;
    }
}
// To put remove messages from queue
struct msg dequeue() {
  // get message infront of queue, update pointer and deincrement
    struct msg message = A_message_queue.buffer[A_message_queue.front];
    A_message_queue.front = (A_message_queue.front + 1) % MAX_BUFFER_SIZE;
    A_message_queue.size--;
    return message;
}

// Function to calculate checksum 
int compute_checksum(struct pkt packet) {
    int checksum = packet.seqnum + packet.acknum;
    for (int i = 0; i < 20; i++) {
        checksum += packet.payload[i]; 
    }
    printf("Computed Checksum: %d\n", checksum);
    return checksum;
}

// Function to check if a packet is corrupted
int is_corrupted(struct pkt packet) {
  // if check_packet result is true (packet is corrupted)
    int result = compute_checksum(packet) != packet.checksum;
    printf("Corruption Check: %s\n", result ? "True (corrupted)" : "False (not corrupted)");
    return result;
}

// Function to create and initialize a packet
struct pkt create_packet(struct msg message, int seqnum) {
    struct pkt packet;
    packet.seqnum = seqnum;
    packet.acknum = 0; // not needed in packets
    // when message.data is a fixed size of 20 bytes
    int message_length = 20;
    for (int i = 0; i < message_length; i++) {
      // Copy only the actual message
        packet.payload[i] = message.data[i];
    }
    packet.payload[message_length] = '\0'; // Ensure null-termination
    packet.checksum = compute_checksum(packet); // Compute checksum
    return packet;
}

// Function to create and initialize an ACK packet
struct pkt create_ack_packet(int acknum) {
    struct pkt ack_packet;
    ack_packet.seqnum = 0; // not needed in ACK packets
    ack_packet.acknum = acknum;
    memset(ack_packet.payload, 0, sizeof(ack_packet.payload)); // Clear payload
    ack_packet.checksum = compute_checksum(ack_packet); // Compute checksum
    return ack_packet;
}

/* called from layer 5, passed the data to be sent to other side */
void A_output(struct msg message)
{
  printf("A_output called with message: %s\n", message.data);
  enqueue(message); // enqueue the incoming message
  printf("Messaged Buffered\n");
  // if we are not waiting for an ack dequeue and send packet, if yes; do nothing wait for ack
  if (!A_waiting_for_ack && A_message_queue.size > 0) {
    struct msg buffered_message = dequeue();
    printf("Buffered message ready to send\n");
    // Create packet from dequeued message
    struct pkt packet = create_packet(buffered_message, A_seqnum); 
    printf("A_output: Sending packet: SeqNum=%d, Checksum=%d\n", packet.seqnum, packet.checksum);
    tolayer3(0, packet); // packet to be sent into the network
    starttimer(0, TIMEOUT);
    printf("A_output: Timer started for SeqNum=%d\n", packet.seqnum);
    A_waiting_for_ack = 1; // Waiting for ack flag
    A_last_packet = packet; // store the sent packet
      printf("Stored the sent packet '%s', SeqNum=%d, Checksum=%d\n", packet.payload, packet.seqnum, packet.checksum);
    }   
}

/* called from layer 3, when a packet arrives for layer 4 */
void A_input(struct pkt packet)
{
  printf("A_input: ACK received: %d, Expected ACK: %d\n", packet.acknum, A_expected_ack);
  // check the packet is not corrupted and the acknum in packet matches the expected acknum at A
  if (!is_corrupted(packet) && packet.acknum == A_expected_ack) {
    stoptimer(0); // stops the timer for the packet
    printf("A_input: ACK is valid. Stopping timer.\n");
    // toggles the next sequence and ack num
    A_expected_ack = 1 - A_expected_ack;
    A_seqnum = 1 - A_seqnum;
    A_waiting_for_ack = 0; // Reset waiting for ack flag
    printf("A_input: SeqNum toggled to: %d, Waiting for ACK reset\n", A_seqnum);
    printf("ACK received. SeqNum toggled to: %d\n", A_seqnum);

    // Check if there is a buffered message and send it
    if (A_message_queue.size > 0) {
      struct msg buffered_message = dequeue();
      struct pkt new_packet = create_packet(buffered_message, A_seqnum); 
      printf("A_input: Sending buffered packet: SeqNum=%d\n", new_packet.seqnum);
      tolayer3(0, new_packet);
      starttimer(0, TIMEOUT);
      A_waiting_for_ack = 1;
      A_last_packet = new_packet; // update the last packet
      printf("Stored the sent packet '%s', SeqNum=%d, Checksum=%d\n", new_packet.payload, new_packet.seqnum, new_packet.checksum);

    }
  } else {
    printf("A_input: Invalid ACK or corrupted packet received.\n");
    // tolayer3(0, A_last_packet); // retransmit
    // starttimer(0, TIMEOUT);
  }
}

/* called when A's timer goes off */
void A_timerinterrupt()
{
  // printf("A_timerinterrupt called. Resending last packet.\n");
  printf("Resending last packet: SeqNum=%d\n", A_last_packet.seqnum);
  tolayer3(0, A_last_packet); // retransmit
  starttimer(0, TIMEOUT);

}  

/* the following routine will be called once (only) before any other */
/* entity A routines are called. You can use it to do any initialization */
void A_init()
{
  printf("A_init called. Initializing variables.\n");
  A_seqnum = 0; 
  A_expected_ack = 0;
  A_waiting_for_ack = 0; // for buffer
  A_buffered = 0; // buffer flag
  A_message_queue.front = 0; // front the queue
  A_message_queue.end = -1; // end of the queue
  A_message_queue.size = 0;

}

/* called from layer 3, when a packet arrives for layer 4 at B*/
void B_input(struct pkt packet)
{
    printf("B_input: Packet received. SeqNum: %d, Expected SeqNum: %d\n", packet.seqnum, B_expected_seqnum);
    // check if the packet is not corrupted and the sequence number is = to the expected sequence number at B
    // if yes process the new packet and send to upper layer 
    if (!is_corrupted(packet)) {
      if (packet.seqnum == B_expected_seqnum) {
        printf("B_input: Packet is valid. Sending to layer 5 and ACK back.\n");
        char temp_payload[21]; // Temporary buffer for 20 characters + null terminator
        // Manually copy the first 20 characters to print for debugging
        for (int i = 0; i < 20; i++) {
            temp_payload[i] = packet.payload[i];
        }
        temp_payload[20] = '\0'; // Explicitly null-terminate 
        // tolayer5(1, temp_payload);
        tolayer5(1, packet.payload);
        printf("B_input: Packet: %s is sent to layer 5\n", temp_payload);
        // create ACK packet 
        B_last_ackpacket = create_ack_packet(B_expected_seqnum);
        tolayer3(1, B_last_ackpacket);
        printf("B_ack: Ack packet sent to layer 3: AckNum: %d, Checksum: %d\n", B_last_ackpacket.acknum, B_last_ackpacket.checksum);
        B_last_acknowledged_seqnum = B_expected_seqnum;
        B_expected_seqnum = 1 - B_expected_seqnum;
        printf("ACK sent from B. AckNum: %d\n", B_last_ackpacket.acknum);

      } else if (packet.seqnum == B_last_acknowledged_seqnum) {
          // This is a retransmission of the last acknowledged packet. Resend ACK.
          tolayer3(1, B_last_ackpacket);
          printf("B_input: Resent ACK for retransmitted packet: AckNum: %d, Checksum: %d\n", B_last_ackpacket.acknum, B_last_ackpacket.checksum);
      } else {
          // Packet is out of order or unexpected
          printf("B_input: Received unexpected packet SeqNum: %d\n", packet.seqnum);
        }   
    } else {
        printf("B_input: Packet is corrupted or unexpected SeqNum.\n");
    }
}

/* the following routine will be called once (only) before any other */
/* entity B routines are called. You can use it to do any initialization */
void B_init()
{
  printf("B_init called. Initializing variables.\n");
  B_expected_seqnum = 0;
  int B_last_acknowledged_seqnum = -1;

}
