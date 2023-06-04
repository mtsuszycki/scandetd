

struct list_head {
	void *next;
	void *prev;
};


static inline int is_empty(struct list_head *head)
{
	return head->next == head;
}


#define LIST_HEAD(name) \
	struct list_head name = { &name, &name }

#define INIT_LIST_HEAD(ptr) do { \
	(ptr)->next = (ptr); (ptr)->prev = (ptr); \
} while (0)


	
#define for_each(e,l) 	for((e)=(l).next; (e)!=(void *) &(l); (e)=(e)->next)
#define addto_list(e,l)	{(e)->prev=(l).prev;		\
			 (e)->prev->next=(e);		\
			 (e)->next=(typeof(e))&l;	\
			 (l).prev=(e);}

#define delfrom_list(e,l) {(e)->prev->next=(e)->next;	\
			   (e)->next->prev=(e)->prev; }

#define dellist(e,l)	{ void *p;			\
			  for((e)=(l).next; (e)!=(void *) &(l); (e)=p){	\
			  	p=(e)->next;		\
				delfrom_list((e),(l));	\
				free((e));		\
			  }				\
			}		
