# filter files with this variable we add new mimetype in this variable to expand more variables
FilterAllowed=[
    # "application/x-dosexec",
    # "application/x-msdownload",
    "text/html",
    "application/octet-stream",
    "application/x-rar",
    "application/gzip",
    "application/zip",
    "application/vnd.ms-powerpoint",
    "application/pdf",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
]
NotAllowedScripts=[
    "text/x-msdos-batch",
    "text/plain",
    "text/html"
]
NotAllowedLanguageScripts=[
    "PowerShell",
    "Batchfile"
]
# directory for file scanning
FilterDir="./scanfolder"

# module class to make our terminal prints with colors
class terminalColors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
