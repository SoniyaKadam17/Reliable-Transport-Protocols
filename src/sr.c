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

/********* STUDENTS WRITE THE NEXT SEVEN ROUTINES *********/

// #define WINDOW_SIZE 10
#define TIMEOUT 50
#define MAX_SEQ_NUM 600
// estimated maximum buffer size value
#define MAX_BUFFER_SIZE 1000 

int WINDOW_SIZE;

// Global variables for A
int A_send_base; // to keep track of sent but not ack'ed packets
int A_nextseqnum; // Next sequence number to be sent
int *A_acknowledged; // keep track of ACK'ed packets received by A
struct pkt *A_buffer; // buffer for messages/packets within the window
// to check if the timer is already running
int is_timer_running = 0;

// Global variables for B
int B_expected_seqnum; // Next expected sequence number at receiver
struct pkt *B_buffer; // buffer out of order packets within the window
int *B_received; // // to keep track of received packets
int B_send_base;

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
  packet.acknum = 0;
  memcpy(packet.payload, message.data, sizeof(message.data));
  packet.checksum = compute_checksum(packet); // Compute checksum
  return packet;
}

// Function to create and initialize an ACK packet
struct pkt create_ack_packet(int acknum) {
  struct pkt packet;
  packet.acknum = acknum;
  packet.seqnum = 0; // not used in ACK packets
  memset(packet.payload, 0, sizeof(packet.payload)); // clear payload
  packet.checksum = compute_checksum(packet);
  return packet;
}

void process_buffered_packets() {
  // Loop as long as there are consecutive received packets in the buffer
  while (B_received[B_expected_seqnum % WINDOW_SIZE]) {
    // Deliver the packet to the application layer
    tolayer5(1, B_buffer[B_expected_seqnum % WINDOW_SIZE].payload);
    printf("B_input: Delivered buffered packet to layer 5, SeqNum: %d\n", B_expected_seqnum - 1);
    // Clear the flag to indicate the packet at this position has been processed
    B_received[B_expected_seqnum % WINDOW_SIZE] = 0;
    // Increment the expected sequence number
    B_expected_seqnum = (B_expected_seqnum + 1) % MAX_SEQ_NUM;
  }
}

int is_within_window(int seqnum, int base, int window_size) {
  int upper_bound = (base + window_size) % MAX_SEQ_NUM;
  if (base < upper_bound) {
    // Normal case without wrapping
    return seqnum >= base && seqnum < upper_bound;
  } else {
    // When the window wraps around the maximum sequence number
    return seqnum >= base || seqnum < upper_bound;
  }
}

/* called from layer 5, passed the data to be sent to other side */
void A_output(struct msg message)
{
  printf("A_output called with message: %s\n", message.data);
  // If window is not full, send packet
  if (A_nextseqnum < A_send_base + WINDOW_SIZE) {
    struct pkt packet = create_packet(message, A_nextseqnum);
    // store packet for later
    A_buffer[A_nextseqnum % WINDOW_SIZE] = packet;
    // send packet
    tolayer3(0, packet);
    printf("Packet sent from A to B: SeqNum=%d, Checksum=%d\n", packet.seqnum, packet.checksum);
   // Start timer if it's the first packet in the window
    if (!is_timer_running) {
      starttimer(0, TIMEOUT);
      is_timer_running = 1;
      printf("Timer started for packet with SeqNum=%d\n", packet.seqnum);
    }
    // increment seqnum and wrap sequence number within max seqnum
    A_nextseqnum = (A_nextseqnum + 1) % MAX_SEQ_NUM;
    printf("Next sequence number %d\n", A_nextseqnum);
  } else {
      // Window is full, buffer the message for later
      enqueue(message);
      printf("Sender window full. Message enqueued.\n");
    }   
}

/* called from layer 3, when a packet arrives for layer 4 */
void A_input(struct pkt packet) {
  if (!is_corrupted(packet)) {
    // upper bound of the sender's window 
    int window_upper_bound = (A_send_base + WINDOW_SIZE) % MAX_SEQ_NUM;

    // Check if the acknum is within the sender's window
    if (packet.acknum >= A_send_base && ((A_send_base < window_upper_bound && packet.acknum < window_upper_bound) ||
      (A_send_base > window_upper_bound && (packet.acknum < window_upper_bound || packet.acknum >= A_send_base)))) {
      
      // Mark packet as acknowledged
      A_acknowledged[packet.acknum % WINDOW_SIZE] = 1;
      printf("ACK received for SeqNum: %d\n", packet.acknum);

      // Slide window forward
      while (A_acknowledged[A_send_base % WINDOW_SIZE]) {
        A_acknowledged[A_send_base % WINDOW_SIZE] = 0;  // Reset acknowledgment
        A_send_base = (A_send_base + 1) % MAX_SEQ_NUM;  // Move window forward

        // Send next buffered message if available
        if (!is_empty(&A_message_queue)) {
          struct msg message = dequeue();
          A_output(message);  // Send buffered message
        }
      }

      // Restart or stop timer based on window state
      if (A_send_base == A_nextseqnum) {
        stoptimer(0);
      } else {
        starttimer(0, TIMEOUT);
      }
    }
  }
}

/* called when A's timer goes off */
void A_timerinterrupt()
{
  printf("Timer interrupt at A. Resending unacknowledged packets.\n");
  // Check if the oldest packet has not been acknowledged
  if (!A_acknowledged[A_send_base % WINDOW_SIZE]) {
    tolayer3(0, A_buffer[A_send_base % WINDOW_SIZE]);
    printf("Resending packet from A to B: SeqNum=%d\n", A_buffer[A_send_base % WINDOW_SIZE].seqnum);
    starttimer(0, TIMEOUT); // Restart timer for the oldest packet
    is_timer_running = 1;
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
  A_buffer = (struct pkt *)malloc(WINDOW_SIZE * sizeof(struct pkt));
  if (!A_buffer) {
    fprintf(stderr, "Memory allocation failed for A_buffer\n");
    exit(1);
  }
  A_acknowledged = (int *)malloc(WINDOW_SIZE * sizeof(int));
  if (!A_acknowledged) {
    fprintf(stderr, "Memory allocation failed for A_acknowledged\n");
    exit(1);
  }
  memset(A_acknowledged, 0, WINDOW_SIZE * sizeof(int));
}

// B_input function with updated handling of out-of-order packets
void B_input(struct pkt packet) {
  printf("B_input: Packet received. SeqNum: %d, Expected SeqNum: %d\n", packet.seqnum, B_expected_seqnum);

  if (!is_corrupted(packet)) {
    // find the lower and upper bounds 
    int window_lower_bound = B_expected_seqnum;
    int window_upper_bound = (B_expected_seqnum + WINDOW_SIZE) % MAX_SEQ_NUM;
    // Check if the packet is within the receiver's window
    if ((window_lower_bound <= window_upper_bound && packet.seqnum >= window_lower_bound && packet.seqnum < window_upper_bound) ||
      (window_lower_bound > window_upper_bound && (packet.seqnum >= window_lower_bound || packet.seqnum < window_upper_bound))) {
      
      // Send ACK for the received packet
      tolayer3(1, create_ack_packet(packet.seqnum));
      printf("B_input: Sending ACK for SeqNum: %d\n", packet.seqnum);

      if (packet.seqnum == B_expected_seqnum) {
        // Deliver in-order packet
        tolayer5(1, packet.payload);
        B_expected_seqnum = (B_expected_seqnum + 1) % MAX_SEQ_NUM;

        // Deliver any buffered, now in-order packets
        process_buffered_packets();
      } else if (!B_received[packet.seqnum % WINDOW_SIZE]) {
        // Buffer out-of-order packets
        B_buffer[packet.seqnum % WINDOW_SIZE] = packet;
        B_received[packet.seqnum % WINDOW_SIZE] = 1;
      }
    }
  }
}

/* the following rouytine will be called once (only) before any other */
/* entity B routines are called. You can use it to do any initialization */
void B_init()
{
  printf("B_init called. Initializing variables.\n");
  WINDOW_SIZE = getwinsize();
  B_send_base = 0;
  B_expected_seqnum = 0;
  B_buffer = (struct pkt *)malloc(WINDOW_SIZE * sizeof(struct pkt));
  if (!B_buffer) {
    fprintf(stderr, "Memory allocation failed for A_buffer\n");
    exit(1);
  }
  B_received = (int *)malloc(WINDOW_SIZE * sizeof(int));
  if (!B_received) {
    fprintf(stderr, "Memory allocation failed for B_received\n");
    exit(1);
  }
  memset(B_received, 0, WINDOW_SIZE * sizeof(int));
}

void A_cleanup() {
    free(A_buffer);
}

void B_cleanup() {
    free(B_buffer);
}
