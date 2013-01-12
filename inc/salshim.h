#ifndef MTLS_INC_SALSHIM_H
#define MTLS_INC_SALSHIM_H

// if SAL annotations aren't available, define them out to do nothing

#ifndef _In_

#define _In_
#define _In_opt_
#define _In_reads_bytes_
#define _Inout_
#define _Out_
#define _Out_opt_
#define _Outptr_
#define _Out_writes_bytes_(a)
#define _Out_writes_bytes_all_(a)
#define _Check_return_
#define _Ret_notnull_
#define _Return_type_success_(a)
#define _Use_decl_annotations_
#define _Must_inspect_result_

#endif // defined _In_

#endif
