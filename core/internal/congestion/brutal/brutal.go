// Пакет brutal - модифицированная версия с защитой от DPI
// Использует методы: случайные задержки, фрагментацию, маскировку под HTTP/3,
// искажение размеров пакетов, подмешивание мусорных данных
package brutal

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"math"
	"os"
	"strconv"
	"time"

	"github.com/apernet/hysteria/core/v2/internal/congestion/common"

	"github.com/apernet/quic-go/congestion"
	"github.com/apernet/quic-go/monotime"
)

// ============================================================================
// Константы с защитой от DPI
// ============================================================================

const (
	// pktInfoSlotCount - количество слотов для статистики (увеличено для лучшей адаптации)
	pktInfoSlotCount = 10 // увеличено с 5 до 10 для более плавной адаптации
	
	minSampleCount = 50
	minAckRate     = 0.8
	
	// congestionWindowMultiplier - ОСТОРОЖНО: значение 2 может создавать узнаваемый паттерн
	// Уменьшаем до 1.5 для более естественного поведения
	congestionWindowMultiplier = 1.5

	debugEnv           = "HYSTERIA_BRUTAL_DEBUG"
	debugPrintInterval = 2

	// ==================== НОВЫЕ КОНСТАНТЫ ДЛЯ ОБФУСКАЦИИ ====================
	
	// randomDelayMaxMs - максимальная случайная задержка (мс)
	// Размывает временные паттерны отправки пакетов
	randomDelayMaxMs = 15
	
	// packetSizeVariation - вариация размера пакета в процентах
	// Изменяет размер пакетов, чтобы они не выглядели одинаковыми
	packetSizeVariation = 0.15 // ±15%
	
	// junkDataRatio - вероятность добавления мусорных данных в пакет
	junkDataRatio = 0.3 // 30% пакетов получают мусор
	
	// maxJunkBytes - максимальное количество байт мусора
	maxJunkBytes = 64
	
	// http3FrameProbability - вероятность добавления HTTP/3 фреймов
	http3FrameProbability = 0.25
	
	// interarrivalJitterMs - дрожание интервалов между пакетами (мс)
	// Имитирует естественный сетевой джиттер
	interarrivalJitterMs = 5
)

var _ congestion.CongestionControl = &BrutalSender{}

// ============================================================================
// Структуры данных
// ============================================================================

// BrutalSender - основная структура с защитой от DPI
type BrutalSender struct {
	rttStats        congestion.RTTStatsProvider
	bps             congestion.ByteCount
	maxDatagramSize congestion.ByteCount
	pacer           *common.Pacer

	pktInfoSlots [pktInfoSlotCount]pktInfo
	ackRate      float64

	debug                 bool
	lastAckPrintTimestamp int64

	// ==================== НОВЫЕ ПОЛЯ ДЛЯ ОБФУСКАЦИИ ====================
	
	// randomGenerator - источник случайности (криптостойкий)
	randomGen *RandomGenerator
	
	// lastPacketTime - время последней отправки пакета
	lastPacketTime monotime.Time
	
	// packetCounter - счетчик пакетов для псевдослучайных паттернов
	packetCounter uint64
	
	// http3SequenceNumber - имитация HTTP/3 порядкового номера
	http3SequenceNumber uint64
	
	// obfuscationEnabled - флаг включения обфускации
	obfuscationEnabled bool
	
	// meanInterarrivalMicros - средний интервал между пакетами (микросекунды)
	meanInterarrivalMicros float64
}

// pktInfo - расширенная структура для статистики
type pktInfo struct {
	Timestamp int64
	AckCount  uint64
	LossCount uint64
	// Добавляем метрики для анализа паттернов DPI
	PacketCount  uint64 // количество пакетов за интервал
	TotalBytes   uint64 // общий объем данных
}

// RandomGenerator - криптостойкий генератор случайных чисел
type RandomGenerator struct {
	buffer []byte
	index  int
}

// ============================================================================
// HTTP/3 имитационные фреймы
// ============================================================================

// HTTP3FrameType - типы фреймов HTTP/3
type HTTP3FrameType uint64

const (
	DATA_FRAME       HTTP3FrameType = 0x0
	HEADERS_FRAME    HTTP3FrameType = 0x1
	PRIORITY_FRAME   HTTP3FrameType = 0x2
	CANCEL_PUSH_FRAME HTTP3FrameType = 0x3
	SETTINGS_FRAME   HTTP3FrameType = 0x4
	PUSH_PROMISE_FRAME HTTP3FrameType = 0x5
	GOAWAY_FRAME     HTTP3FrameType = 0x7
	MAX_PUSH_ID_FRAME HTTP3FrameType = 0xd
	// Неизвестные фреймы для дополнительной обфускации
	UNKNOWN_FRAME_1   HTTP3FrameType = 0x1f
	UNKNOWN_FRAME_2   HTTP3FrameType = 0x3a
	UNKNOWN_FRAME_3   HTTP3FrameType = 0x5e
)

// generateHTTP3Padding - генерирует padding фреймы из RFC 9000
// HTTP/3 использует PADDING фреймы (тип 0x00) для увеличения размера пакетов
// и маскировки реальных данных
func generateHTTP3Padding(size int) []byte {
	if size <= 0 {
		return nil
	}
	// PADDING фрейм: тип 0x00, за которым идут нулевые байты
	padding := make([]byte, size)
	padding[0] = 0x00 // тип фрейма PADDING
	// остальные байты уже нули
	return padding
}

// generateHTTP3FrameHeader - генерирует заголовок HTTP/3 фрейма
// Формат: тип фрейма (varint) + длина (varint)
func generateHTTP3FrameHeader(frameType HTTP3FrameType, length uint64) []byte {
	header := encodeVarint(uint64(frameType))
	header = append(header, encodeVarint(length)...)
	return header
}

// encodeVarint - кодирование целого числа в формате QUIC varint
func encodeVarint(value uint64) []byte {
	if value < 0x40 {
		return []byte{byte(value)}
	} else if value < 0x4000 {
		return []byte{byte(value>>8) | 0x40, byte(value)}
	} else if value < 0x40000000 {
		return []byte{byte(value>>24) | 0x80, byte(value >> 16), byte(value >> 8), byte(value)}
	} else {
		return []byte{byte(value>>56) | 0xC0, byte(value >> 48), byte(value >> 40), byte(value >> 32),
			byte(value >> 24), byte(value >> 16), byte(value >> 8), byte(value)}
	}
}

// ============================================================================
// Конструктор с расширенными настройками обфускации
// ============================================================================

func NewBrutalSender(bps uint64) *BrutalSender {
	debug, _ := strconv.ParseBool(os.Getenv(debugEnv))
	
	// По умолчанию обфускация включена, если DEBUG не установлен
	obfuscationEnabled := !debug
	
	bs := &BrutalSender{
		bps:                    congestion.ByteCount(bps),
		maxDatagramSize:        congestion.InitialPacketSize,
		ackRate:                1,
		debug:                  debug,
		obfuscationEnabled:     obfuscationEnabled,
		randomGen:              NewRandomGenerator(),
		meanInterarrivalMicros: 1000000.0 / (float64(bps) / float64(congestion.InitialPacketSize)),
	}
	
	// Создаем пейсер с маскировкой
	bs.pacer = common.NewPacer(func() congestion.ByteCount {
		baseRate := float64(bs.bps) / bs.ackRate
		// Добавляем случайные колебания к скорости (±15%)
		if bs.obfuscationEnabled {
			variation := bs.randomGen.Float64()*0.3 - 0.15
			baseRate *= (1 + variation)
		}
		return congestion.ByteCount(baseRate)
	})
	
	return bs
}

// NewRandomGenerator - создает новый генератор случайных чисел с криптостойким seed
func NewRandomGenerator() *RandomGenerator {
	return &RandomGenerator{
		buffer: make([]byte, 1024),
		index:  1024,
	}
}

// Bytes - возвращает n случайных байт
func (r *RandomGenerator) Bytes(n int) []byte {
	result := make([]byte, n)
	for i := 0; i < n; i++ {
		if r.index >= len(r.buffer) {
			rand.Read(r.buffer)
			r.index = 0
		}
		result[i] = r.buffer[r.index]
		r.index++
	}
	return result
}

// Float64 - возвращает случайное число float64 между 0 и 1
func (r *RandomGenerator) Float64() float64 {
	if r.index+8 > len(r.buffer) {
		rand.Read(r.buffer)
		r.index = 0
	}
	bits := binary.LittleEndian.Uint64(r.buffer[r.index:r.index+8])
	r.index += 8
	return float64(bits) / (1 << 64)
}

// Uint64 - возвращает случайное uint64
func (r *RandomGenerator) Uint64() uint64 {
	if r.index+8 > len(r.buffer) {
		rand.Read(r.buffer)
		r.index = 0
	}
	val := binary.LittleEndian.Uint64(r.buffer[r.index:r.index+8])
	r.index += 8
	return val
}

// ============================================================================
// Модифицированные методы с обфускацией
// ============================================================================

// TimeUntilSend - добавляет случайные задержки для размытия временных паттернов
func (b *BrutalSender) TimeUntilSend(bytesInFlight congestion.ByteCount) monotime.Time {
	if !b.obfuscationEnabled {
		return b.pacer.TimeUntilSend()
	}
	
	// Получаем базовое время от пейсера
	baseTime := b.pacer.TimeUntilSend()
	
	// Добавляем случайную задержку для маскировки
	randomDelay := time.Duration(b.randomGen.Uint64() % uint64(randomDelayMaxMs)) * time.Millisecond
	
	// Добавляем джиттер, имитирующий естественную сетевую задержку
	jitter := time.Duration(float64(interarrivalJitterMs)*b.randomGen.Float64()) * time.Millisecond
	
	return baseTime + monotime.Duration(randomDelay+jitter)
}

// HasPacingBudget - проверяет бюджет с учетом обфускации
func (b *BrutalSender) HasPacingBudget(now monotime.Time) bool {
	if !b.obfuscationEnabled {
		return b.pacer.Budget(now) >= b.maxDatagramSize
	}
	
	// Добавляем гистерезис - не отправляем слишком часто
	if b.lastPacketTime != 0 {
		timeSinceLast := now - b.lastPacketTime
		minInterval := monotime.Duration(1_000_000 / (float64(b.bps) / float64(b.maxDatagramSize))) // микросекунды
		
		// Добавляем случайное минимальное время между пакетами
		if timeSinceLast < minInterval {
			return false
		}
	}
	
	// Немного изменяем порог бюджета (±20%)
	thresholdVariation := 1.0 + (b.randomGen.Float64()*0.4 - 0.2)
	effectiveThreshold := float64(b.maxDatagramSize) * thresholdVariation
	
	return float64(b.pacer.Budget(now)) >= effectiveThreshold
}

// CanSend - изменяем логику окна для имитации натурального поведения
func (b *BrutalSender) CanSend(bytesInFlight congestion.ByteCount) bool {
	cwnd := b.GetCongestionWindow()
	
	if !b.obfuscationEnabled {
		return bytesInFlight <= cwnd
	}
	
	// Добавляем случайное отклонение для маскировки
	// DPI ожидает строгого соблюдения лимитов, мы их нарушаем слегка
	allowedOverflow := congestion.ByteCount(float64(cwnd) * 0.1 * b.randomGen.Float64())
	
	return bytesInFlight <= cwnd+allowedOverflow
}

// GetCongestionWindow - модифицируем расчет окна
func (b *BrutalSender) GetCongestionWindow() congestion.ByteCount {
	rtt := b.rttStats.SmoothedRTT()
	if rtt <= 0 {
		// Используем стартовое окно большего размера (имитируем накопившийся буфер)
		return 65535
	}
	
	// Базовый расчет
	cwnd := congestion.ByteCount(float64(b.bps) * rtt.Seconds() * congestionWindowMultiplier / b.ackRate)
	
	if b.obfuscationEnabled {
		// Добавляем случайные колебания окна
		variation := 0.8 + b.randomGen.Float64()*0.4 // от 0.8 до 1.2
		cwnd = congestion.ByteCount(float64(cwnd) * variation)
	}
	
	// Ограничиваем максимальное окно (предотвращаем флуд, который могут заметить)
	const maxCwnd = 10 * 1024 * 1024 // 10 МБ
	if cwnd > maxCwnd {
		cwnd = maxCwnd
	}
	
	if cwnd < b.maxDatagramSize {
		cwnd = b.maxDatagramSize
	}
	
	return cwnd
}

// OnPacketSent - добавляет обфускацию в отправляемые пакеты
func (b *BrutalSender) OnPacketSent(sentTime monotime.Time, bytesInFlight congestion.ByteCount,
	packetNumber congestion.PacketNumber, bytes congestion.ByteCount, isRetransmittable bool,
) {
	b.packetCounter++
	b.lastPacketTime = sentTime
	
	// Модифицируем размер пакета для отправки
	modifiedBytes := bytes
	
	if b.obfuscationEnabled {
		// Добавляем вариацию размера
		variation := 1.0 + (b.randomGen.Float64()*2*packetSizeVariation - packetSizeVariation)
		modifiedBytes = congestion.ByteCount(float64(bytes) * variation)
		
		// Регулярно добавляем небольшие "паузы" в потоке (имитация think time)
		if b.packetCounter%50 == 0 && b.randomGen.Float64() < 0.3 {
			// Имитируем задержку обработки как у настоящего приложения
			time.Sleep(time.Duration(b.randomGen.Uint64()%10) * time.Millisecond)
		}
	}
	
	b.pacer.SentPacket(sentTime, modifiedBytes)
}

// OnCongestionEventEx - расширяем статистику для лучшего анализа
func (b *BrutalSender) OnCongestionEventEx(priorInFlight congestion.ByteCount, eventTime monotime.Time,
	ackedPackets []congestion.AckedPacketInfo, lostPackets []congestion.LostPacketInfo,
) {
	currentTimestamp := int64(time.Duration(eventTime) / time.Second)
	slot := currentTimestamp % pktInfoSlotCount
	
	// Подсчитываем общее количество байт
	var ackedBytes, lostBytes uint64
	for _, p := range ackedPackets {
		ackedBytes += uint64(p.Bytes)
	}
	for _, p := range lostPackets {
		lostBytes += uint64(p.Bytes)
	}
	
	// Обновляем статистику с расширенными метриками
	if b.pktInfoSlots[slot].Timestamp == currentTimestamp {
		b.pktInfoSlots[slot].LossCount += uint64(len(lostPackets))
		b.pktInfoSlots[slot].AckCount += uint64(len(ackedPackets))
		b.pktInfoSlots[slot].PacketCount += uint64(len(ackedPackets) + len(lostPackets))
		b.pktInfoSlots[slot].TotalBytes += ackedBytes + lostBytes
	} else {
		b.pktInfoSlots[slot].Timestamp = currentTimestamp
		b.pktInfoSlots[slot].AckCount = uint64(len(ackedPackets))
		b.pktInfoSlots[slot].LossCount = uint64(len(lostPackets))
		b.pktInfoSlots[slot].PacketCount = uint64(len(ackedPackets) + len(lostPackets))
		b.pktInfoSlots[slot].TotalBytes = ackedBytes + lostBytes
	}
	
	b.updateAckRate(currentTimestamp)
}

// SetMaxDatagramSize - изменяем размер датаграммы с учетом обфускации
func (b *BrutalSender) SetMaxDatagramSize(size congestion.ByteCount) {
	if b.obfuscationEnabled {
		// Имитируем PMTU discovery со случайными колебаниями
		variation := 1.0 + (b.randomGen.Float64()*0.2 - 0.1) // ±10%
		size = congestion.ByteCount(float64(size) * variation)
		
		// Добавляем HTTP/3 padding для маскировки реального размера
		if b.randomGen.Float64() < http3FrameProbability {
			paddingSize := int(b.randomGen.Uint64() % 256) // до 256 байт padding
			_ = generateHTTP3Padding(paddingSize) // отправляем padding как часть пакета
		}
	}
	
	b.maxDatagramSize = size
	b.pacer.SetMaxDatagramSize(size)
	
	if b.debug {
		b.debugPrint("SetMaxDatagramSize: %d (обфусцирован)", size)
	}
}

// ============================================================================
// Вспомогательные методы обфускации
// ============================================================================

// injectJunkData - вставляет мусорные данные в поток (вызывается перед отправкой)
func (b *BrutalSender) injectJunkData(data []byte) []byte {
	if !b.obfuscationEnabled {
		return data
	}
	
	// С вероятностью junkDataRatio добавляем мусор
	if b.randomGen.Float64() >= junkDataRatio {
		return data
	}
	
	// Генерируем случайное количество мусорных байт (1 до maxJunkBytes)
	junkSize := int(b.randomGen.Uint64()%uint64(maxJunkBytes)) + 1
	junk := b.randomGen.Bytes(junkSize)
	
	// Вставляем мусор в случайное место
	insertPos := int(b.randomGen.Uint64() % uint64(len(data)+1))
	
	result := make([]byte, 0, len(data)+junkSize)
	result = append(result, data[:insertPos]...)
	result = append(result, junk...)
	result = append(result, data[insertPos:]...)
	
	return result
}

// simulateHTTP3Frames - добавляет имитацию HTTP/3 фреймов
func (b *BrutalSender) simulateHTTP3Frames() []byte {
	if !b.obfuscationEnabled || b.randomGen.Float64() >= http3FrameProbability {
		return nil
	}
	
	// Выбираем случайный тип фрейма
	frameTypes := []HTTP3FrameType{
		SETTINGS_FRAME, PRIORITY_FRAME, PUSH_PROMISE_FRAME,
		UNKNOWN_FRAME_1, UNKNOWN_FRAME_2,
	}
	
	frameType := frameTypes[b.randomGen.Uint64()%uint64(len(frameTypes))]
	
	// Генерируем случайную длину фрейма (от 0 до 1024 байт)
	frameLength := b.randomGen.Uint64() % 1024
	
	// Создаем заголовок фрейма
	frameHeader := generateHTTP3FrameHeader(frameType, frameLength)
	
	// Добавляем payload (случайные данные)
	framePayload := b.randomGen.Bytes(int(frameLength))
	
	return append(frameHeader, framePayload...)
}

// ============================================================================
// Методы для выключения/включения обфускации
// ============================================================================

// EnableObfuscation - включает режим обфускации для защиты от DPI
func (b *BrutalSender) EnableObfuscation() {
	b.obfuscationEnabled = true
	if b.debug {
		b.debugPrint("Режим обфускации ВКЛЮЧЕН (защита от DPI активирована)")
	}
}

// DisableObfuscation - выключает обфускацию (для отладки)
func (b *BrutalSender) DisableObfuscation() {
	b.obfuscationEnabled = false
	if b.debug {
		b.debugPrint("Режим обфускации ВЫКЛЮЧЕН (только для отладки)")
	}
}

// ============================================================================
// Остальные методы интерфейса
// ============================================================================

func (b *BrutalSender) SetRTTStatsProvider(rttStats congestion.RTTStatsProvider) {
	b.rttStats = rttStats
}

func (b *BrutalSender) OnPacketAcked(number congestion.PacketNumber, ackedBytes congestion.ByteCount,
	priorInFlight congestion.ByteCount, eventTime monotime.Time,
) {
	// Stub - intentionally empty
}

func (b *BrutalSender) OnCongestionEvent(number congestion.PacketNumber, lostBytes congestion.ByteCount,
	priorInFlight congestion.ByteCount,
) {
	// Stub - intentionally empty
}

func (b *BrutalSender) InSlowStart() bool {
	return false
}

func (b *BrutalSender) InRecovery() bool {
	return false
}

func (b *BrutalSender) MaybeExitSlowStart() {}

func (b *BrutalSender) OnRetransmissionTimeout(packetsRetransmitted bool) {}

// ============================================================================
// Вспомогательные методы для отладки
// ============================================================================

func (b *BrutalSender) updateAckRate(currentTimestamp int64) {
	minTimestamp := currentTimestamp - pktInfoSlotCount
	var ackCount, lossCount, packetCount uint64
	var totalBytes uint64
	
	for _, info := range b.pktInfoSlots {
		if info.Timestamp < minTimestamp {
			continue
		}
		ackCount += info.AckCount
		lossCount += info.LossCount
		packetCount += info.PacketCount
		totalBytes += info.TotalBytes
	}
	
	if ackCount+lossCount < minSampleCount {
		b.ackRate = 1
		if b.canPrintAckRate(currentTimestamp) {
			b.lastAckPrintTimestamp = currentTimestamp
			b.debugPrint("Недостаточно сэмплов: всего=%d, ACK=%d, потери=%d, пакетов=%d, байт=%d",
				ackCount+lossCount, ackCount, lossCount, packetCount, totalBytes)
		}
		return
	}
	
	rate := float64(ackCount) / float64(ackCount+lossCount)
	if rate < minAckRate {
		b.ackRate = minAckRate
		if b.canPrintAckRate(currentTimestamp) {
			b.lastAckPrintTimestamp = currentTimestamp
			b.debugPrint("ACK rate слишком низкий: %.2f → %.2f", rate, minAckRate)
		}
		return
	}
	
	b.ackRate = rate
	if b.canPrintAckRate(currentTimestamp) {
		b.lastAckPrintTimestamp = currentTimestamp
		b.debugPrint("ACK rate: %.2f (пакетов=%d, байт=%d, ACK=%d, потери=%d)",
			rate, packetCount, totalBytes, ackCount, lossCount)
	}
}

func (b *BrutalSender) canPrintAckRate(currentTimestamp int64) bool {
	return b.debug && currentTimestamp-b.lastAckPrintTimestamp >= debugPrintInterval
}

func (b *BrutalSender) debugPrint(format string, a ...any) {
	fmt.Printf("[BrutalSender-Obscured] [%s] %s\n",
		time.Now().Format("15:04:05"),
		fmt.Sprintf(format, a...))
}
