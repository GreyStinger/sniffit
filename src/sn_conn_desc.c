/* Connection description detection file                                 */
/*   - by: Brecht Claerhout                                              */


/* Simple PORT BASED detection */

unsigned short src_port_h = ntohs(tcphead.source);
unsigned short dst_port_h = ntohs(tcphead.destination);

/*** FTP sessions ********************************************************/
if( (src_port_h==FTP_DATA_1)||(dst_port_h==FTP_DATA_1) )
  {strcpy(desc_string, "FTP DATA");}

if( (src_port_h==FTP_1)||(dst_port_h==FTP_1) )
  {
  if(info->DATA_len==0)
    strcpy(desc_string, "FTP");
  if(info->DATA_len>5)
    {
    const unsigned char *data= sp+PROTO_HEAD+info->IP_len+info->TCP_len;

    strcpy(desc_string,"FTP: ");
    j=5;                                                 /* 5 = "FTP: " */
    for(i=0;i<info->DATA_len;i++)
      {
      if( (isalnum(data[i]) || ispunct(data[i]) || data[i]==' ')&&(j<(*DESC_LEN)-1) )
        {desc_string[j]=data[i]; desc_string[j+1]=0; j++; }
      else
        {if( (isspace(data[i]) && data[i]!=' ')&&(j<(*DESC_LEN)-1) )
           {desc_string[j]=' '; desc_string[j+1]=0; j++; }
        }
      }
    }
  }

/*** TELNET sessions *****************************************************/
if( (src_port_h==TELNET_1)||(dst_port_h==TELNET_1) )
  {strcpy(desc_string, "TELNET");}

/*** SSH sessions ********************************************************/
if( (src_port_h==SSH_1)||(dst_port_h==SSH_1) )
  {strcpy(desc_string, "Secure Shell");}

/*** MAIL sessions *****************************************************/
if( (src_port_h==MAIL_1)||(dst_port_h==MAIL_1) )
  {strcpy(desc_string, "MAIL");}

/*** IDENT **************************************************************/
if( (src_port_h==IDENT_1)||(dst_port_h==IDENT_1) )
  {strcpy(desc_string, "IDENT");}

/*** IRC ***************************************************************/
if( (src_port_h==IRC_1)||(dst_port_h==IRC_1) )
  {strcpy(desc_string, "IRC");}

/*** X11 sessions *******************************************************/
if( (src_port_h==X11_1)||(dst_port_h==X11_1) )
  {strcpy(desc_string, "X-Windows");}

/*** HTTP ***************************************************************/
if( (src_port_h==HTTP_1)||(src_port_h==HTTP_2)||
    (src_port_h==HTTP_3)||(src_port_h==HTTP_4)
  )
  {
  strcpy(desc_string, "HTTP");
  }

if( (dst_port_h==HTTP_1)||(dst_port_h==HTTP_2) ||
    (dst_port_h==HTTP_3)||(dst_port_h==HTTP_4)
  )
  {
  if(info->DATA_len==0)
    strcpy(desc_string, "HTTP");
  if(info->DATA_len>5)
    {
    const unsigned char *data= sp+PROTO_HEAD+info->IP_len+info->TCP_len;

    strcpy(desc_string,"HTTP: ");
    j=6;                                                 /* 5 = "HTTP: " */
    for(i=0;i<info->DATA_len;i++)
      if( (isalnum(data[i]) || ispunct(data[i]) || data[i]==' ')&&(j<(*DESC_LEN)-1) )
        {desc_string[j]=data[i]; desc_string[j+1]=0; j++; }
      else
        {if( (isspace(data[i]) && data[i]!=' ')&&(j<(*DESC_LEN)-1) )
           {desc_string[j]=' '; desc_string[j+1]=0; j++; }
        }
    }
  }

/*** DYNAMIC SERVICE DETECTION ******************************************/
if(strcmp(desc_string, "Unknown") == 0) {
    struct servent *service;
    unsigned short dst_port = tcphead.destination;
    unsigned short src_port = tcphead.source;

    service = getservbyport((int)dst_port, "tcp");
    if(service != NULL && service->s_name != NULL) {
        strncpy(desc_string, service->s_name, (*DESC_LEN) - 1);
        desc_string[(*DESC_LEN) - 1] = '\0';
        for(i = 0; desc_string[i] != '\0'; i++) {
            if(desc_string[i] >= 'a' && desc_string[i] <= 'z')
                desc_string[i] = desc_string[i] - 32;
        }
    }
    else {
        service = getservbyport((int)src_port, "tcp");
        if(service != NULL && service->s_name != NULL) {
            strncpy(desc_string, service->s_name, (*DESC_LEN) - 1);
            desc_string[(*DESC_LEN) - 1] = '\0';
            for(i = 0; desc_string[i] != '\0'; i++) {
                if(desc_string[i] >= 'a' && desc_string[i] <= 'z')
                    desc_string[i] = desc_string[i] - 32;
            }
        }
        else {
            strcpy(desc_string, "Unknown");
        }
    }
}

