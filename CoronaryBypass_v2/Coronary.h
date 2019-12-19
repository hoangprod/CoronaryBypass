#pragma once

NTSTATUS PrintMsg(PSPECIAL_BUFFER data);
BOOLEAN CheckElementExistsViaOpen(PUNICODE_STRING puPath);
NTSTATUS GetExistenceStatus(PUNICODE_STRING puPath, PIO_STATUS_BLOCK);