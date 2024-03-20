// banner.go
package banner

import (
	"github.com/gookit/color"
)

// PrintBanner 打印程序介绍图案
func PrintBanner() {
	banner := `
 _   _    _    ____  _   _    _    ____ ___  ____  
| | | |  / \  |  _ \| | | |  / \  / ___/ _ \|  _ \ 
| |_| | / _ \ | |_) | |_| | / _ \| |  | | | | |_) |
|  _  |/ ___ \|  __/|  _  |/ ___ \ |__| |_| |  __/ 
|_| |_/_/   \_\_|   |_| |_/_/   \_\____\___/|_|    
                                                   
                linux 应急工具包v1.0
`
	color.Green.Println(banner)
}
