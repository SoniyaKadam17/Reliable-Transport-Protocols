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

// window size 
// #define WINDOW_SIZE 10
// estimated maximum buffer size value
#define MAX_BUFFER_SIZE 1000 
// estimated timeout value
#define TIMEOUT 20 // average of 5 time units to arrive at the other side 

int WINDOW_SIZE;

// Global variables for A
int A_send_base; // to keep track of sent but not ack'ed packets
int A_nextseqnum; // Next sequence number to be sent
int A_last_acked_seqnum; // Last ACK received by A
struct pkt *A_buffer; // buffer for messages/packets within the window
int is_timer_running;

// Global variables for B
int B_expected_seqnum; // Next expected sequence number at receiver
int B_last_acknowledged_seqnum;
struct pkt B_last_ackpacket; // store the last ACK packet sent by B

// Buffer queue to store messages when the sender's window is full
struct message_queue {
    struct msg buffer[MAX_BUFFER_SIZE];
    int front, end, size;
} A_message_queue;

// Initialize the message queue
void init_message_queue(struct message_queue *q) {
    q->front = q->end = 0;
    q->size = 0;
}

// Check if the queue is full
int is_full(struct message_queue *q) {
    return q->size == MAX_BUFFER_SIZE;
}

// Check if the queue is empty
int is_empty(struct message_queue *q) {
    return q->size == 0;
}

// To put messages in a queue
void enqueue(struct msg message) {
  // Check if the queue is full first
  if (is_full(&A_message_queue)) {
    fprintf(stderr, "Message queue overflow.\n");
    exit(1);
    }
    // Add message to queue and update pointers and size of the queue
    A_message_queue.buffer[A_message_queue.end] = message;
    A_message_queue.end = (A_message_queue.end + 1) % MAX_BUFFER_SIZE;
    A_message_queue.size++;
    printf("Message enqueued, queue size now %d\n", A_message_queue.size); 
}
// To put remove messages from queue
struct msg dequeue() {
  // Check if the queue is empty first
  if (is_empty(&A_message_queue)) {
    fprintf(stderr, "Attempt to dequeue from an empty buffer.\n");
    exit(1);
  }
  // Retrieve message from queue and update pointers and size of the queue
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
    // Copy only the actual message
    memcpy(packet.payload, message.data, sizeof(message.data));
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

// Send all packets in the window that haven't been sent yet
void send_window_packets(void) {
  // while the next sequence number is within the window and queue is not empty
  while (A_nextseqnum < A_send_base + WINDOW_SIZE && !is_empty(&A_message_queue)) {
    // Dequeue and create packet  
    struct msg message = dequeue();
    struct pkt packet = create_packet(message, A_nextseqnum);
    // store in buffer for potential retransmission
    A_buffer[A_nextseqnum % WINDOW_SIZE] = packet;
    // send packet and increment seqnum
    tolayer3(0, packet);
    A_nextseqnum++;
  }
  // Start the timer if there are unacknowledged packets
  if (A_send_base < A_nextseqnum) {
    starttimer(0, TIMEOUT);
    is_timer_running = 1;
  }
}

/* called from layer 5, passed the data to be sent to other side */
void A_output(struct msg message)
{
  printf("A_output called with message: %s\n", message.data);
  // If window is not full, send packet
  if (A_nextseqnum < A_send_base + WINDOW_SIZE) {
    struct pkt packet = create_packet(message, A_nextseqnum);
    A_buffer[A_nextseqnum % WINDOW_SIZE] = packet;
    // send packet
    tolayer3(0, packet);
    printf("A_output: Sending packet: SeqNum=%d, Checksum=%d\n", packet.seqnum, packet.checksum);
   // Start timer if it's the first packet in the window
    if (A_send_base == A_nextseqnum) {
      starttimer(0, TIMEOUT); 
      printf("Timer started for packet with SeqNum=%d\n", packet.seqnum); 
    }
    // increment seqnum
    A_nextseqnum++;
    printf("Next sequence number %d\n", A_nextseqnum);
  } else {
      // Window is full, buffer the message for later
      enqueue(message);
      printf("Message buffered, queue size now %d\n", A_message_queue.size); 
    }   
}

/* called from layer 3, when a packet arrives for layer 4 */
void A_input(struct pkt packet)
{
  printf("A_input called with ACK: %d\n", packet.acknum);
  // Check if the packet is not corrupted and the acknum is within the window
  if (!is_corrupted(packet) && packet.acknum >= A_send_base && packet.acknum < A_nextseqnum) {
    printf("ACK is valid, sliding window forward\n");
    // Slide the window forward based on the received ack number
    A_send_base = packet.acknum + 1;
    // // Update the last ACKed sequence number
    A_last_acked_seqnum = packet.acknum; 
    printf("Last ACKed sequence number is ACKNum=%d\n", A_last_acked_seqnum); 
    // Stop the timer if all outstanding packets are acknowledged
    if (A_send_base == A_nextseqnum) {
      stoptimer(0);
      is_timer_running = 0;
      printf("All outstanding packets acknowledged. Timer stopped.\n");
    } else {
      stoptimer(0);
      starttimer(0, TIMEOUT);
      is_timer_running = 1;
      printf("Timer restarted for the outstanding packets.\n");
    }  
      // Check the buffer queue for any messages that can now be sent
      send_window_packets();
    } 
}

/* called when A's timer goes off */
void A_timerinterrupt() {
  printf("A_timerinterrupt called. Resending window starting from A_send_base.\n");
  starttimer(0, TIMEOUT);
  // retransmit all packets from the start of the window
  for (int i = A_send_base; i < A_nextseqnum; i++) {
    tolayer3(0, A_buffer[i % WINDOW_SIZE]);
  }
}

/* the following routine will be called once (only) before any other */
/* entity A routines are called. You can use it to do any initialization */
void A_init()
{
  printf("A_init called. Initializing variables.\n");
  WINDOW_SIZE = getwinsize();
  A_send_base = 0;
  A_nextseqnum = 0;
  init_message_queue(&A_message_queue);
  // Dynamically allocate the buffer based on the window size
  A_buffer = (struct pkt *)malloc(WINDOW_SIZE * sizeof(struct pkt)); 
    if (A_buffer == NULL) {
      fprintf(stderr, "Memory allocation for A_buffer failed\n");
      // Handle malloc failure
      exit(1);
    }
}

/* called from layer 3, when a packet arrives for layer 4 at B*/
void B_input(struct pkt packet)
{
    printf("B_input: Packet received. SeqNum: %d, Expected SeqNum: %d\n", packet.seqnum, B_expected_seqnum);
    // Check if the packet is not corrupted
    if (!is_corrupted(packet)) {
      if (packet.seqnum == B_expected_seqnum) {
        printf("B_input: Packet is valid. Sending to layer 5 and ACK back.\n");
        tolayer5(1, packet.payload);
        printf("B_input: Packet: %s is sent to layer 5\n", packet.payload);
        // Create and send a new ACK packet
        B_last_ackpacket = create_ack_packet(B_expected_seqnum);
        printf("B_input: Sending ACK: %d\n", B_last_ackpacket.acknum);
        tolayer3(1, B_last_ackpacket);
        printf("B_ack: Ack packet sent to layer 3: AckNum: %d, Checksum: %d\n", B_last_ackpacket.acknum, B_last_ackpacket.checksum);
        // increment sequence number
        B_expected_seqnum++;

    } else {
        // For any other packet; duplicate, retransmission, Out-of-order, resend the last ACK
        printf("B_input: Wrong packet received, resending last ACK.\n");
        tolayer3(1, B_last_ackpacket);
        printf("B_input: Resent ACK: AckNum: %d, Checksum: %d\n", B_last_ackpacket.acknum, B_last_ackpacket.checksum);
    }
  }
}

/* the following routine will be called once (only) before any other */
/* entity B routines are called. You can use it to do any initialization */
void B_init()
{
  printf("B_init called. Initializing variables.\n");
  B_expected_seqnum = 0;
  WINDOW_SIZE = getwinsize();

}

void A_cleanup() {
  // Free the dynamically allocated buffer
  free(A_buffer); 
}
