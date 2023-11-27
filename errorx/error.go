package errorx

// ErrCode 表示错误码
type ErrCode int

//go:generate stringer -type ErrCode -linecomment -output error_code.go
// -type指定类型
// -output code_string.go 指定生成的文件名称
// -linecomment 将注释名称作为错误描述

// 定义错误码
const (
	ERR_CODE_SUCCESS        = iota
	ERR_CODE_OK             // OK
	ERR_CODE_INVALID_PARAMS // 无效参数
	ERR_CODE_TIMEOUT        // 超时
)
