/* pcapslicer.c: Extract traffic out of pcap dumps based on a list of given
 *               IP addresses.
 * Author:       Kamran Riaz Khan <krkhan@inspirated.com>
 */

#include <arpa/inet.h>
#include <glib.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <pcap/pcap.h>
#include <net/ethernet.h>
#include <netinet/ip.h>

typedef struct {
  pcap_dumper_t *writer;
  char *fname;
} HashTableEntry;

void print_hash_table(gpointer key, gpointer value, gpointer data)
{
  printf("%s\n", (char *) key);
}

void free_hash_table(gpointer key, gpointer value, gpointer data)
{
  HashTableEntry *entry = (HashTableEntry *) value;

  free(key);
  if(entry->writer != NULL) {
    pcap_dump_close(entry->writer);
  }
  free(entry->fname);
  g_free(entry);
}

void fill_hash_table(GHashTable *hash, char *listfname, pcap_t *reader)
{
  FILE *listfd;

  listfd = fopen(listfname, "r");

  if(listfd == NULL) {
    perror("fopen");
    exit(EXIT_FAILURE);
  }

  char ip[INET_ADDRSTRLEN], *nl;

  while(!feof(listfd)) {
    if(fgets(ip, INET_ADDRSTRLEN, listfd) == NULL) {
      continue;
    }

    // strip newline characters
    nl = strrchr(ip, '\r');
    if (nl) {
      *nl = '\0';
    }
    nl = strrchr(ip, '\n');
    if (nl) {
      *nl = '\0';
    }

    struct in_addr ia;

    if(inet_pton(AF_INET, ip, &ia) == 1) {
      // if ip is valid
      if(g_hash_table_lookup(hash, ip) == NULL) {
        // and is not present in the hashtable
        // create a pcap dumper and associate it with the ip
        char *key, *fname;
        HashTableEntry *entry = g_new0(HashTableEntry, 1);

        key = strdup(ip);

        asprintf(&fname, "%s.pcap", ip);
        entry->writer = NULL;
        // pcap_dumper_t *writer = pcap_dump_open(reader, fname);
        // entry->writer = writer;
        entry->fname = fname;

        g_hash_table_insert(hash, key, entry);
      }
    }
  }

  fclose(listfd);
}

int main(int argc, char *argv[])
{
  if(argc < 3) {
    fprintf(stderr, "Usage: %s pcapfile iplist\n", argv[0]);
    exit(EXIT_FAILURE);
  }

  pcap_t *reader;
  char errbuf[PCAP_ERRBUF_SIZE];
  reader = pcap_open_offline(argv[1], errbuf);

  if(reader == NULL) {
    fprintf(stderr, "Could not open pcap file: %s\n", errbuf); 
    exit(EXIT_FAILURE);
  }

  // key: ip addresses (char *)
  // value: pcap dumpers (pcap_dumper_t *)
  GHashTable* hash = g_hash_table_new(g_str_hash, g_str_equal);

  fill_hash_table(hash, argv[2], reader);

  fprintf(stdout, "iplist:\n");
  g_hash_table_foreach(hash, print_hash_table, NULL);

  struct pcap_pkthdr header;
  const u_char *packet;

  while((packet = pcap_next(reader, &header)) != NULL) {
    u_char *pkt_ptr = (u_char *) packet;

    struct ether_header *ether = (struct ether_header *) pkt_ptr;
    pkt_ptr += sizeof(struct ether_header);

    if(htons(ether->ether_type) != ETHERTYPE_IP) {
      continue;
    }

    struct ip *ip = (struct ip *) pkt_ptr;

    if(ip->ip_v != 4) {
      continue;
    }

    // processing only ipv4 packets from this point onwards

    char ip_src[INET_ADDRSTRLEN], ip_dst[INET_ADDRSTRLEN];

    inet_ntop(AF_INET, &(ip->ip_src), ip_src, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(ip->ip_dst), ip_dst, INET_ADDRSTRLEN);

    HashTableEntry *entry;

    // if src or dst ip is in the hashtable, use the associated
    // dumper for writing the packet to the respective pcap file
    if((entry = g_hash_table_lookup(hash, ip_src)) != NULL) {
      if(entry->writer == NULL) {
        pcap_dumper_t *writer = pcap_dump_open(reader, entry->fname);
        entry->writer = writer;
      }
      pcap_dump((u_char *) entry->writer, &header, packet);
    }
    if((entry = g_hash_table_lookup(hash, ip_dst)) != NULL) {
      if(entry->writer == NULL) {
        pcap_dumper_t *writer = pcap_dump_open(reader, entry->fname);
        entry->writer = writer;
      }
      pcap_dump((u_char *) entry->writer, &header, packet);
    }
  }

  g_hash_table_foreach(hash, free_hash_table, NULL);

  exit(EXIT_SUCCESS);
}

