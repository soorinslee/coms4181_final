struct MSG* getnextmsg(char* username);

struct MSG {
    int code;
    char* sender;
    char* message;
};
