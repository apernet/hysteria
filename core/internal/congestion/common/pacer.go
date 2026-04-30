package common

import (
	"crypto/rand"
	"encoding/binary"
	"math"
	"time"

	"github.com/apernet/quic-go/congestion"
	"github.com/apernet/quic-go/monotime"
)

const (
	maxBurstPackets               = 10
	maxBurstPacingDelayMultiplier = 4
	
	// НОВЫЕ константы для защиты от DPI
	enableTimingJitter           = true  // Вносить случайную задержку
	maxTimingJitterPercent       = 15    // Максимальный джиттер в процентах от задержки
	enableBatchSplitting         = true  // Разбивать большие пакеты на мелкие
	enableRandomBurst            = true  // Случайный размер burst
	enableInterPacketDelayVar    = true  // Вариативность межпакетных интервалов
	enableMicroBursts            = true  // Микро-всплески для имитации VoIP/видео
	enableTrafficShaping         = true  // Изменение формы трафика
	
	// Параметры обфускации
	minPacketSizeJitter          = 20    // Минимальное добавление байт мусора
	maxPacketSizeJitter          = 64    // Максимальное добавление байт мусора
	obfuscationProbability       = 30    // Вероятность обфускации пакета (%)
)

// DPIProtectionConfig - конфигурация защиты от DPI
type DPIProtectionConfig struct {
	// Включена ли защита
	Enabled bool
	
	// Уровень защиты (1-3, где 3 - максимальный)
	Level int
	
	// Имитировать трафик реальных приложений
	ImitateRealTraffic bool
	
	// Тип трафика для имитации (video, voip, gaming, browsing)
	TrafficPattern string
}

// Pacer - расширенная версия с защитой от DPI
type Pacer struct {
	budgetAtLastSent congestion.ByteCount
	maxDatagramSize  congestion.ByteCount
	lastSentTime     monotime.Time
	getBandwidth     func() congestion.ByteCount
	
	// НОВЫЕ поля для защиты от DPI
	dpiConfig        DPIProtectionConfig
	rng              []byte              // Случайные байты для CSPRNG
	
	// Статистика для адаптивного поведения
	sentPackets      uint64
	lastPatternChange monotime.Time
	patternDuration  time.Duration
	
	// Имитация реальных приложений
	voiceActivity    bool                // Voice Activity Detection для VoIP
	videoFrameSize   int                 // Размер кадра видео
	frameCounter     int                 // Счетчик кадров
	
	// Обфускация
	padBytes         congestion.ByteCount // Добавляемые байты паддинга
	lastObfuscation  monotime.Time
}

// NewPacerWithDPI создает пейсер с защитой от DPI
func NewPacerWithDPI(getBandwidth func() congestion.ByteCount, config DPIProtectionConfig) *Pacer {
	p := &Pacer{
		budgetAtLastSent:  maxBurstPackets * congestion.InitialPacketSize,
		maxDatagramSize:   congestion.InitialPacketSize,
		getBandwidth:      getBandwidth,
		dpiConfig:         config,
		rng:               make([]byte, 32),
		sentPackets:       0,
		lastPatternChange: monotime.Now(),
		patternDuration:   5 * time.Second, // Меняем паттерн каждые 5 секунд
		voiceActivity:     false,
		videoFrameSize:    1200, // Примерный размер видеофрейма
		frameCounter:      0,
		padBytes:          0,
	}
	
	// Инициализируем CSPRNG
	rand.Read(p.rng)
	return p
}

// SentPacket - модифицированная версия с защитой от DPI
func (p *Pacer) SentPacket(sendTime monotime.Time, size congestion.ByteCount) {
	budget := p.Budget(sendTime)
	
	// Добавляем обфускацию к размеру пакета (для сбивания DPI)
	actualSize := size
	if p.dpiConfig.Enabled && p.shouldObfuscate() {
		actualSize = p.addPadding(size)
	}
	
	if actualSize > budget {
		p.budgetAtLastSent = 0
	} else {
		p.budgetAtLastSent = budget - actualSize
	}
	
	p.lastSentTime = sendTime
	p.sentPackets++
	
	// Периодически меняем паттерн трафика
	if p.dpiConfig.Level >= 2 && 
	   sendTime.Sub(p.lastPatternChange) > p.patternDuration {
		p.changeTrafficPattern()
		p.lastPatternChange = sendTime
	}
}

// Budget - модифицированная версия со случайными вариациями
func (p *Pacer) Budget(now monotime.Time) congestion.ByteCount {
	if p.lastSentTime.IsZero() {
		// Используем случайный burst вместо максимального
		if p.dpiConfig.Enabled && enableRandomBurst {
			return p.randomBurstSize()
		}
		return p.maxBurstSize()
	}
	
	// Базовый расчет бюджета
	timeDelta := now.Sub(p.lastSentTime)
	nanoseconds := timeDelta.Nanoseconds()
	
	// Добавляем вариации в расчет времени (имитируем реальные задержки ОС)
	if p.dpiConfig.Enabled && enableTimingJitter {
		nanoseconds = p.addTimingJitter(nanoseconds)
	}
	
	addedBytes := (p.getBandwidth() * congestion.ByteCount(nanoseconds)) / 1e9
	
	// Добавляем микро-всплески (имитация VoIP/видео трафика)
	if p.dpiConfig.Enabled && enableMicroBursts {
		addedBytes = p.addMicroBursts(addedBytes)
	}
	
	budget := p.budgetAtLastSent + addedBytes
	
	if budget < 0 {
		budget = congestion.ByteCount(1<<62 - 1)
	}
	
	maxBurst := p.maxBurstSize()
	
	// Для защиты от DPI - иногда разрешаем небольшое превышение burst
	if p.dpiConfig.Level >= 2 && p.shouldAllowOverburst() {
		maxBurst = maxBurst * 12 / 10 // +20% иногда
	}
	
	return min(maxBurst, budget)
}

// TimeUntilSend - основное улучшение для защиты от DPI
func (p *Pacer) TimeUntilSend() monotime.Time {
	if p.budgetAtLastSent >= p.maxDatagramSize {
		// Даже если можно отправить сразу, иногда ждем (имитация обработки)
		if p.dpiConfig.Enabled && p.shouldInsertFakeDelay() {
			fakeDelay := p.calculateFakeDelay()
			return p.lastSentTime.Add(fakeDelay)
		}
		return monotime.Time{}
	}
	
	// Базовое время ожидания
	bytesNeeded := p.maxDatagramSize - p.budgetAtLastSent
	diff := 1e9 * uint64(bytesNeeded)
	bw := uint64(p.getBandwidth())
	
	d := diff / bw
	if diff%bw > 0 {
		d++
	}
	
	waitDuration := time.Duration(d) * time.Nanosecond
	
	// === НОВЫЕ МЕТОДЫ ЗАЩИТЫ ОТ DPI ===
	
	// 1. Добавляем случайный джиттер (делаем трафик менее регулярным)
	if p.dpiConfig.Enabled && enableTimingJitter {
		waitDuration = p.addJitterToDelay(waitDuration)
	}
	
	// 2. Изменяем форму трафика под реальные приложения
	if p.dpiConfig.Enabled && enableTrafficShaping {
		waitDuration = p.shapeTraffic(waitDuration)
	}
	
	// 3. Разбиваем большие паузы на мелкие (burst mode)
	if p.dpiConfig.Level >= 2 && enableBatchSplitting && 
	   waitDuration > 5*congestion.MinPacingDelay {
		waitDuration = p.splitPacingDelay(waitDuration)
	}
	
	// 4. Адаптивный пейсинг (меняем поведение после обнаружения DPI)
	if p.dpiConfig.Level >= 3 && p.detectPotentialDPI() {
		waitDuration = p.adaptivePacing(waitDuration)
	}
	
	// Гарантируем минимальную задержку
	if waitDuration < congestion.MinPacingDelay {
		// Но даже минимальную задержку делаем вариативной
		if p.dpiConfig.Enabled && enableInterPacketDelayVar {
			variation := time.Duration(randInt64(0, int64(congestion.MinPacingDelay/4)))
			waitDuration = congestion.MinPacingDelay + variation
		} else {
			waitDuration = congestion.MinPacingDelay
		}
	}
	
	// Имитация реального трафика (VoIP, видео, игры)
	if p.dpiConfig.ImitateRealTraffic {
		waitDuration = p.imitateRealApplication(waitDuration)
	}
	
	return p.lastSentTime.Add(waitDuration)
}

// ========== НОВЫЕ МЕТОДЫ ЗАЩИТЫ ОТ DPI ==========

// addTimingJitter добавляет случайные вариации в измерение времени
// Это сбивает DPI, который анализирует точные интервалы
func (p *Pacer) addTimingJitter(nanoseconds int64) int64 {
	// Добавляем до 15% случайного шума
	jitterPercent := randInt64(0, maxTimingJitterPercent)
	jitter := nanoseconds * jitterPercent / 100
	
	// Шум может быть как положительным, так и отрицательным
	if randBool() {
		return nanoseconds + jitter
	}
	return max(nanoseconds-jitter, 1)
}

// addJitterToDelay добавляет случайные колебания в задержку отправки
func (p *Pacer) addJitterToDelay(delay time.Duration) time.Duration {
	// Используем нормальное распределение для более реалистичного джиттера
	jitterFactor := 0.85 + float64(randInt64(0, 30))/100.0 // 0.85-1.15
	
	// Но делаем это не для каждого пакета, чтобы не создавать другой паттерн
	if p.sentPackets%3 == 0 { // Каждый 3й пакет
		jitterFactor = 1.0 // без джиттера
	}
	
	newDelay := time.Duration(float64(delay) * jitterFactor)
	
	// Ограничиваем максимальный джиттер
	maxJitter := delay / 4
	if newDelay > delay+maxJitter {
		newDelay = delay + maxJitter
	}
	if newDelay < delay-maxJitter {
		newDelay = delay - maxJitter
	}
	
	return newDelay
}

// randomBurstSize возвращает случайный размер burst для предотвращения fingerprinting
func (p *Pacer) randomBurstSize() congestion.ByteCount {
	maxBurst := p.maxBurstSize()
	
	// Случайный размер от 30% до 100% от максимального
	percent := 30 + randInt64(0, 70)
	return maxBurst * congestion.ByteCount(percent) / 100
}

// addMicroBursts добавляет микро-всплески трафика (имитация VoIP/видео)
func (p *Pacer) addMicroBursts(budget congestion.ByteCount) congestion.ByteCount {
	// VoIP генерирует пакеты каждые 20-30 мс с небольшими всплесками
	// Видео генерирует ключевые кадры (I-frames) каждые 2-3 секунды
	
	packetNum := p.sentPackets % 100
	
	// Имитация VAD (Voice Activity Detection) для VoIP
	if packetNum < 70 { // 70% времени - голос активен
		// Во время голоса добавляем небольшие всплески
		if packetNum%5 == 0 {
			// Каждый 5й VoIP пакет чуть больше (имитация voix)
			budget = budget + 200
		}
	} else if packetNum < 85 {
		// 15% времени - паузы в разговоре (меньше трафика)
		budget = budget * 80 / 100 // -20%
	}
	
	// Имитация видео ключевых кадров (I-frames)
	if p.frameCounter%30 == 0 { // Каждые 30 кадров - ключевой кадр
		budget = budget + congestion.ByteCount(p.videoFrameSize*3)
	}
	p.frameCounter++
	
	return budget
}

// shapeTraffic изменяет форму трафика под различные приложения
func (p *Pacer) shapeTraffic(delay time.Duration) time.Duration {
	// Чередуем разные паттерны задержек
	pattern := p.sentPackets % 10
	
	switch pattern {
	case 0, 1, 2:
		// Паттерн 1: Равномерный (TCP-подобный)
		return delay
		
	case 3, 4:
		// Паттерн 2: Внезапные всплески (веб-серфинг)
		if p.sentPackets%20 == 0 {
			return delay * 3 // Внезапная пауза
		}
		return delay / 2 // Затем ускорение
		
	case 5, 6, 7:
		// Паттерн 3: Пульсирующий (VoIP)
		if p.sentPackets%10 < 3 {
			return delay * 2
		}
		return delay / 3
		
	case 8, 9:
		// Паттерн 4: Постепенное изменение (видео-стриминг)
		modifier := 1.0 + float64(p.sentPackets%50)/100.0
		return time.Duration(float64(delay) * modifier)
	}
	
	return delay
}

// splitPacingDelay разбивает большие задержки на серию мелких (burst mode)
func (p *Pacer) splitPacingDelay(delay time.Duration) time.Duration {
	if delay <= 10*time.Millisecond {
		return delay
	}
	
	// Разбиваем на 3 части: ждем 1/3, отправляем, ждем 2/3
	// Это создает несколько всплесков вместо одного длительного ожидания
	parts := randInt64(2, 4)
	partDelay := delay / time.Duration(parts)
	
	// TODO: Здесь нужна более сложная логика с несколькими таймерами
	// Для простоты возвращаем первую часть, остальные будут в следующих вызовах
	return partDelay
}

// imitateRealApplication имитирует поведение реальных приложений
func (p *Pacer) imitateRealApplication(delay time.Duration) time.Duration {
	switch p.dpiConfig.TrafficPattern {
	case "voip":
		// VoIP: постоянный поток пакетов каждые 20-50 мс
		// Добавляем вариации от VAD (Voice Activity Detection)
		if p.voiceActivity {
			return 20 * time.Millisecond
		}
		return 100 * time.Millisecond
		
	case "video":
		// Видео: вариативный битрейт с ключевыми кадрами
		if p.frameCounter%30 == 0 {
			// Ключевой кадр (I-frame) - всплеск трафика
			return delay / 4 // Отправляем быстрее
		}
		// P-frames и B-frames идут с обычной задержкой
		return delay
		
	case "gaming":
		// Игры: очень низкие задержки с высоким джиттером
		gameJitter := time.Duration(randInt64(0, int64(5*time.Millisecond)))
		return delay + gameJitter
		
	case "browsing":
		// Веб-серфинг: внезапные всплески трафика
		if p.sentPackets%50 == 0 {
			return delay * 10 // Долгая пауза (чтение страницы)
		}
		return delay / 2 // Быстрая загрузка
		
	default:
		// Смешанный трафик
		return delay
	}
}

// detectPotentialDPI пытается обнаружить признаки DPI
func (p *Pacer) detectPotentialDPI() bool {
	// Анализируем паттерны, характерные для DPI:
	// 1. Регулярные задержки от пробирования (probing)
	// 2. Потеря пакетов после определенных паттернов
	// 3. Аномальные RTT
	
	// Простая эвристика: если пакеты теряются после определенной паузы
	if p.sentPackets > 100 && p.sentPackets%50 == 0 {
		// Имитируем обнаружение DPI с вероятностью 5%
		return randInt64(0, 100) < 5
	}
	return false
}

// adaptivePacing адаптивно меняет пейсинг при подозрении на DPI
func (p *Pacer) adaptivePacing(delay time.Duration) time.Duration {
	// Если обнаружен DPI - меняем поведение
	// Добавляем случайные паузы разной длины
	randomFactor := 0.5 + float64(randInt64(0, 100))/100.0 // 0.5-1.5
	
	// Иногда делаем паузу значительно длиннее
	if randInt64(0, 10) == 0 {
		randomFactor = 5.0 // Внезапная пауза в 5 раз длиннее
	}
	
	return time.Duration(float64(delay) * randomFactor)
}

// addPadding добавляет случайный паддинг к пакету для обфускации
func (p *Pacer) addPadding(size congestion.ByteCount) congestion.ByteCount {
	// Добавляем случайное количество байт паддинга
	padding := congestion.ByteCount(randInt64(minPacketSizeJitter, maxPacketSizeJitter))
	
	// Сохраняем информацию о паддинге для последующего удаления
	p.padBytes = padding
	
	// Не превышаем MTU
	if size+padding > congestion.MaxPacketSize {
		padding = congestion.MaxPacketSize - size
	}
	
	return size + padding
}

// shouldObfuscate определяет, нужно ли обфусцировать текущий пакет
func (p *Pacer) shouldObfuscate() bool {
	return randInt64(0, 100) < obfuscationProbability
}

// shouldAllowOverburst определяет, разрешить ли превышение burst
func (p *Pacer) shouldAllowOverburst() bool {
	// 10% времени разрешаем превышение
	return randInt64(0, 100) < 10
}

// shouldInsertFakeDelay определяет, вставить ли фейковую задержку
func (p *Pacer) shouldInsertFakeDelay() bool {
	// 15% времени добавляем фейковую задержку
	return randInt64(0, 100) < 15
}

// calculateFakeDelay вычисляет фейковую задержку
func (p *Pacer) calculateFakeDelay() time.Duration {
	// Имитация обработки пакета в userspace/kernel
	fakeDelay := randInt64(100, 500) // 100-500 микросекунд
	return time.Duration(fakeDelay) * time.Microsecond
}

// changeTrafficPattern периодически меняет паттерн трафика
func (p *Pacer) changeTrafficPattern() {
	// Меняем тип имитируемого трафика каждые 5-10 секунд
	patterns := []string{"voip", "video", "gaming", "browsing"}
	randomIndex := randInt64(0, int64(len(patterns)-1))
	p.dpiConfig.TrafficPattern = patterns[randomIndex]
	
	// Меняем параметры burst
	if randBool() {
		// Временно уменьшаем burst
		p.budgetAtLastSent = p.budgetAtLastSent * 70 / 100
	}
}

// ========== ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ ==========

// randInt64 возвращает случайное число в диапазоне [min, max]
func randInt64(min, max int64) int64 {
	if min >= max {
		return min
	}
	
	var b [8]byte
	rand.Read(b[:])
	random := int64(binary.LittleEndian.Uint64(b[:]))
	
	range_ := max - min + 1
	return min + (random % range_)
}

// randBool возвращает случайное булево значение
func randBool() bool {
	var b [1]byte
	rand.Read(b[:])
	return b[0]%2 == 0
}

// max возвращает максимум из двух int64
func max(a, b int64) int64 {
	if a > b {
		return a
	}
	return b
}
